# UserGuide.md — Reddit Comment Cleanup Script

This guide walks you through setting up Reddit API access, collecting the values the script needs, and running the script safely.

> **What this script does**
>
> - Lists your own Reddit comments (newest → oldest)
> - Targets comments older than a specified age (`-DaysOld`)
> - Optionally **overwrites** each comment first (default behavior), then deletes it
> - Writes a CSV report and maintains resume state so you can stop/restart without reprocessing

---

## 1) Prerequisites

### PowerShell 7+
This script requires **PowerShell 7 or newer**.

Check your version:

```powershell
$PSVersionTable.PSVersion
```

If that shows `7.x` you’re good.

### Script file location
Place the script file somewhere easy to work from, for example:

- Windows: `C:\Tools\RedditCleanup\`
- macOS/Linux: `~/tools/reddit-cleanup/`

In examples below, the script is named:

- `Invoke-RedditCommentDeath.ps1`

---

## 2) (OAuth mode only) Create a Reddit API “script” app (Client ID + Secret)

You only need this if you choose `-AuthMode OAuth`. The default session-derived mode does **not** require a client id/secret.

### Step-by-step

1. Log in to Reddit in a browser.
2. Open your “apps” preferences page:
   - https://www.reddit.com/prefs/apps
3. Scroll to **Developed Applications**.
4. Click **Create another app…**
5. Fill the form:

   - **name**: any label you want (example: `CommentCleanup`)
   - **type**: select **script**
   - **description**: optional
   - **about url**: optional (can be blank)
   - **redirect uri**: set to `http://localhost` (required, not used by this script)

6. Click **Create app**.

### Collect your app credentials

On the app entry you just created:

- **Client ID**: the short string shown under the app name (often looks like a random mix of letters/numbers)
- **Client Secret**: the value shown beside **secret**

You will pass these to the script as:

- `-ClientId`
- `-ClientSecret`

> Keep these private. Anyone with these values and your auth method could act as your account within the app’s scope.

---

## 3) Choose your authentication method (pick ONE)

This script enforces that you pick exactly one auth mode (default is SessionDerived). Provide only what the chosen mode needs:

- `-AuthMode SessionDerived` (default; single-user)
  - Supply `-SessionAccessToken` (SecureString bearer-style token derived from your signed-in session)
  - Optional: `-SessionApiBaseUri`, `-SessionAuthorizationScheme`, `-SessionSecretName`
  - `-Username` is optional; if omitted, the script adopts the authenticated username returned by `/api/v1/me`.
- `-AuthMode OAuth`
  - Supply **either** `-Password` **or** `-RefreshToken` (not both) plus `-ClientId` and `-ClientSecret`
  - `-Username` is optional but recommended; if omitted, the script adopts the authenticated username after verifying `/api/v1/me`.

If you supply conflicting parameters (both OAuth secrets and session token), the script will stop with an error.

### Option A — Session-derived token (default, single-user)

- Use `-AuthMode SessionDerived` (default).
- Provide your session-derived access token securely: `-SessionAccessToken (Read-Host "Session token" -AsSecureString)`.
- Optional: set `-SessionApiBaseUri` and `-SessionAuthorizationScheme` if your token expects non-default values.
- Treat the token as highly sensitive; do not log it. Prefer OS-protected secret storage if you cache it externally.
- Session reuse may be against Reddit’s terms and can trigger account enforcement. Use interactively, at low volume, and stop if you see challenges/HTML defenses.

### Option B — Password authentication (OAuth)

You provide your Reddit password at runtime as a `SecureString`:

```powershell
-Password (Read-Host "Password" -AsSecureString)
```

Notes:
- The password is converted to plaintext **only** during the token request.
- It is not written to disk by this script.

### Option C — Refresh token authentication (best for repeat runs, OAuth)

A refresh token is an OAuth credential you generate once and then store securely.
It allows the script to obtain access tokens without your password.

You provide the refresh token at runtime as a `SecureString`:

```powershell
-RefreshToken (Read-Host "Refresh Token" -AsSecureString)
```

> This guide includes a practical way to obtain a refresh token in the next section.

---

## 4) (If using RefreshToken) Obtain a Reddit refresh token

A refresh token is issued after you authorize your app. To get one, you’ll make a single authorization request in your browser and then exchange a temporary code for the refresh token.

### 4.1 Build the authorization URL

You will need:

- Your **Client ID**
- Your Reddit **username** (for your own reference)
- A **state** value (any random string)
- A **redirect URI** (use `http://localhost` — must match your app config)

The authorization URL format:

```
https://www.reddit.com/api/v1/authorize?client_id=CLIENT_ID&response_type=code&state=STATE&redirect_uri=http%3A%2F%2Flocalhost&duration=permanent&scope=identity,history,edit,read,submit
```

- `duration=permanent` is what allows a refresh token to be issued.
- Scopes:
  - `identity` lets the script confirm it is authenticated as your username
  - `history` lets it list your comments
  - `edit` lets it overwrite comment text
  - `read` is commonly included for listings
  - `submit` is not required for deleting comments; you can omit it if you prefer

A minimal scope set for this script is typically:

- `identity,history,edit,read`

Example (replace `CLIENT_ID` and `STATE`):

```
https://www.reddit.com/api/v1/authorize?client_id=CLIENT_ID&response_type=code&state=STATE&redirect_uri=http%3A%2F%2Flocalhost&duration=permanent&scope=identity,history,edit,read
```

### 4.2 Authorize in your browser

1. Paste the URL into your browser while logged into Reddit.
2. Reddit will show a consent screen for your app.
3. Click **Allow**.

After you allow, your browser will redirect to something like:

```
http://localhost/?state=STATE&code=AUTH_CODE
```

Copy the value of `code=` — that is your **authorization code**.

### 4.3 Exchange the code for a refresh token

You now need to POST to Reddit’s token endpoint using **Basic auth**:

- Basic auth username: your `ClientId`
- Basic auth password: your `ClientSecret`

And body fields:

- `grant_type=authorization_code`
- `code=AUTH_CODE`
- `redirect_uri=http://localhost`

#### PowerShell helper snippet (one-time use)

Run this in PowerShell 7:

```powershell
$clientId = Read-Host "ClientId"
$clientSecret = Read-Host "ClientSecret"
$code = Read-Host "Authorization code (from browser redirect)"
$redirectUri = "http://localhost"

$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$clientId`:$clientSecret"))
$headers = @{ Authorization = "Basic $basic"; "User-Agent" = "windows:TokenHelper:v1.0 (by /u/yourname)" }
$body = @{
  grant_type   = "authorization_code"
  code         = $code
  redirect_uri = $redirectUri
}

$response = Invoke-RestMethod -Method Post -Uri "https://www.reddit.com/api/v1/access_token" -Headers $headers -Body $body
$response | Format-List
```

In the output, look for:

- `refresh_token`  ✅ this is what you want

Store that refresh token somewhere safe (a password manager is ideal).

When you run the cleanup script, you’ll paste that refresh token when prompted (as a SecureString).

---

## 5) Decide what you want deleted

The script processes comments older than `-DaysOld`.

Examples:

- Delete comments older than **90 days**: `-DaysOld 90`
- Delete comments older than **365 days**: `-DaysOld 365`

### Optional safety margin (`-SafetyHours`)
`-SafetyHours` makes the cutoff *slightly older* to reduce boundary mistakes.

Example:
- `-DaysOld 90 -SafetyHours 24` means “older than 91 days” effectively.

### Optional: exclude specific subreddits (`-ExcludedSubredditsFile`)

If you want to **skip** comments in certain subreddits (leave them untouched), provide a path to a text file containing subreddit names **one per line**.

Rules:
- Blank lines are ignored
- Lines starting with `#` are ignored as comments
- Each entry may be `subname`, `r/subname`, or `/r/subname` (case-insensitive)

Example file:

```text
# excluded-subreddits.txt
AskReddit
r/SomeSub
/r/AnotherSub/
```

Example run:

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90 `
  -ExcludedSubredditsFile "./excluded-subreddits.txt"
```

---

## 6) Decide whether to overwrite before delete

By default, overwrite happens (the script edits comment text, then deletes).

### To delete without overwriting:

```powershell
-SkipOverwrite
```

### Overwrite modes

- `RotatePhrases` (default): swaps in neutral phrases
- `RandomJunk`: random characters
- `FixedText`: always uses your chosen string

Example FixedText:

```powershell
-OverwriteMode FixedText -FixedOverwriteText "[deleted]"
```

---

## 7) Run a safe test first (Dry Run)

A dry run does **not** edit or delete anything. It still:

- Scans your comments
- Applies the age/cutoff logic
- Produces a CSV report
- Exercises authentication and listing

Example (password method):

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

Example (refresh token method):

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -RefreshToken (Read-Host "Refresh Token" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

---

## 8) Run for real

Same as dry run, but without `-DryRun`.

### Default behavior (overwrite + delete)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90
```

### Delete only (no overwrite)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90 `
  -SkipOverwrite
```

### Fixed overwrite text

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90 `
  -OverwriteMode FixedText `
  -FixedOverwriteText "[deleted]"
```

---

## 9) Files the script creates (resume + reporting)

The script creates/updates these files in the current directory by default (you can change paths via parameters):

### 9.1 Checkpoint (`-ResumePath`)
Default: `./reddit_cleanup_state.json`

- Stores the paging cursor (`after`)
- Allows the script to resume after interruptions

### 9.2 Processed ID log (`-ProcessedLogPath`)
Default derived from `ResumePath`, e.g.:

- `./reddit_cleanup_state.processed_ids.log`

- Append-only list of processed comment fullnames (one per line)
- Prevents reprocessing across runs

### 9.3 CSV report (`-ReportPath`)
Default: `./reddit_cleanup_report.csv`

Contains one row per processed comment including:

- `created_utc`
- `permalink`
- `subreddit`
- `fullname`
- `action` (edit+delete / 2xedit+delete / delete)
- `status` (edited/deleted etc.)
- `error` (if any)

---

## 10) Resume behavior (stop and restart safely)

If you stop the script mid-run (Ctrl+C, reboot, network drop), you can re-run the same command and it will:

- Reload the checkpoint cursor
- Reload processed IDs
- Continue without reprocessing already handled comments

If you want a completely fresh run, delete the state/log files:

- `reddit_cleanup_state.json`
- `reddit_cleanup_state.processed_ids.log`
- (optionally) the CSV report

---

## 11) Rate-limits, delays, and batching (what to expect)

This script deliberately slows down to reduce the chance of triggering anti-abuse controls.

Controls you can adjust:

- `-BetweenItemsDelayMin` / `-BetweenItemsDelayMax`
  Wait between processing comments
- `-EditDelaySecondsMin` / `-EditDelaySecondsMax`
  Wait between edit and delete for the same comment
- `-BatchSize` and `-BatchCooldownSeconds`
  Periodic longer pause after batches

Default behavior is conservative and should be safe for long runs.

---

## 12) Two-pass overwrite (optional)

Enable two-pass overwrites for a stable subset of comments:

```powershell
-TwoPassProbability 0.25
```

- Each comment gets a deterministic random value using SHA-256 of:
  - the comment fullname (e.g., `t1_abc123`)
  - a local salt stored on disk
- This makes the selection stable across resumes/re-runs.

Salt file:
- Default derived from `ResumePath`, e.g. `reddit_cleanup_state.two_pass_salt.txt`
- You can set it explicitly with `-TwoPassSaltPath`

---

## 13) Troubleshooting

### “Specify one authentication method” / “not both”
You must provide exactly one:
- `-Password ...` **or**
- `-RefreshToken ...`

### “Authenticated as /u/X but -Username was Y”
The script checks `/api/v1/me` and refuses to run if the authenticated account doesn’t match `-Username`.

Fix: use the correct `-Username` (or fix the credentials you’re providing).

### Unexpected HTML response
The script expects JSON from Reddit API endpoints. HTML often indicates:
- rate-limiting / protection page
- invalid/expired token
- incorrect endpoint usage

Retry later, or reduce request rate by increasing delays/cooldowns.

---

## 14) Quick reference (common commands)

### Dry run (password)
```powershell
./Invoke-RedditCommentDeath.ps1 -ClientId "id" -ClientSecret "secret" -Username "you" -Password (Read-Host "Password" -AsSecureString) -DaysOld 90 -DryRun
```

### Real run (password)
```powershell
./Invoke-RedditCommentDeath.ps1 -ClientId "id" -ClientSecret "secret" -Username "you" -Password (Read-Host "Password" -AsSecureString) -DaysOld 90
```

### Real run (refresh token)
```powershell
./Invoke-RedditCommentDeath.ps1 -ClientId "id" -ClientSecret "secret" -Username "you" -RefreshToken (Read-Host "Refresh Token" -AsSecureString) -DaysOld 90
```

### Delete only (no overwrite)
```powershell
./Invoke-RedditCommentDeath.ps1 -ClientId "id" -ClientSecret "secret" -Username "you" -Password (Read-Host "Password" -AsSecureString) -DaysOld 90 -SkipOverwrite
```

---

## 15) Notes on what the script will and won’t touch

- ✅ Your own **comments**
- ❌ Your posts (submissions)
- ❌ Other users’ content
- ❌ Mod actions, votes, or settings

---
