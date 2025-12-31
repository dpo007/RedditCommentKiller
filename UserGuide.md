# UserGuide.md — Reddit Comment Cleanup Script

This guide walks you through setting up and safely running the Reddit comment cleanup script.

**Auth note (important):**
Authentication is **session-derived token reuse only** (single-user). Why not OAuth? Reddit is axing OAuth API access for regular users, so this script sticks to the session tokens you already have.

> **What this script does**
>
> - Lists **your own Reddit comments** (newest → oldest)
> - Targets comments older than a specified age (`-DaysOld`)
> - Optionally **overwrites** comment content first (default), then deletes it
> - Writes a CSV report
> - Maintains resume state so you can stop/restart safely without reprocessing

---

## 1) Prerequisites

### PowerShell 7+
This script requires **PowerShell 7 or newer**.

Check your version:

```powershell
$PSVersionTable.PSVersion
```

If it shows `7.x`, you’re good.

### Script file location
Place the script somewhere convenient, for example:

- Windows: `C:\Tools\RedditCleanup\`
- macOS/Linux: `~/tools/reddit-cleanup/`

All examples assume the script is named:

- `Invoke-RedditCommentDeath.ps1`

---

## 2) Primary / default authentication: Session-derived token (recommended)

This is the **default and recommended** way to run the script.

### What you provide
- `-SessionAccessToken` (entered at runtime as a `SecureString`)
- `-DaysOld`

---

## 3) How to obtain your Reddit session token (Microsoft Edge)

You will extract an **active session access token** from your logged-in browser session.
This token allows the script to act **as you**, so treat it like a password.

These steps use **Microsoft Edge**, but the process is similar in other Chromium-based browsers.

### Step-by-step (Edge)

1. **Sign in to Reddit**
   - Open Microsoft Edge
   - Go to https://www.reddit.com
   - Ensure you are fully logged in to the correct account

2. **Open Developer Tools**
   - Press **F12**
   - Or right‑click anywhere on the page → **Inspect**

3. **Open the Network tab**
   - In DevTools, click **Network**
   - If the Network tab is empty, refresh the page (**Ctrl+R**) while DevTools is open

4. **Filter for API requests**
   - In the filter box, type:
     ```
     me
     ```
   - Look for a request similar to:
     ```
     https://www.reddit.com/api/v1/me
     ```

5. **Inspect the request**
   - Click the `/api/v1/me` request
   - In the right-hand pane, select the **Headers** tab

6. **Locate the Authorization header**
   - Scroll down to **Request Headers**
   - Find:
     ```
     Authorization: Bearer <LONG_TOKEN_VALUE>
     ```

7. **Copy the token**
   - Copy **only** the value *after* `Bearer `
   - Do **not** include the word `Bearer`

   Example:
   ```
   eyJhbGciOiJSUzI1NiIsImtpZCI6...
   ```

### Common pitfalls
- If you do **not** see an `Authorization` header:
  - Ensure you are logged in
  - Reload the page with DevTools open
  - Try clicking around Reddit (opening your profile often triggers `/api/v1/me`)
- If the token stops working later:
  - Reddit session tokens expire
  - Repeat these steps to obtain a fresh token

### Security warnings
- This token grants **full access equivalent to your logged-in session**
- Do **not** paste it into chat logs, scripts, or files
- Prefer entering it interactively using:
  ```powershell
  Read-Host -AsSecureString
  ```

---

## 4) Dry run (run this first)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

---

## 5) Run for real (default flow)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90
```

---

## 6) Decide what gets deleted

Use `-DaysOld` to control the cutoff.

Examples:
- 90 days → `-DaysOld 90`
- 1 year → `-DaysOld 365`

Optional safety buffer:

```powershell
-SafetyHours 24
```

---

## 7) Overwrite behavior

Default: overwrite then delete.

Disable overwrite:

```powershell
-SkipOverwrite
```

Overwrite modes:
- `RotatePhrases` (default)
- `RandomJunk`
- `FixedText`

---

## 8) Files created

- `reddit_cleanup_state.json` — resume checkpoint
- `reddit_cleanup_state.processed_ids.log` — processed IDs
- `reddit_cleanup_report.csv` — report

---

## 9) Resume behavior

Re-run the same command to continue safely.

Delete state files to start fresh.

---

## 10) Multi-pass mode and Reddit’s ~1k listing cap

- Reddit’s `/user/{name}/comments` listing only exposes roughly the newest 1,000 comments via pagination. If you have more history, older comments may be unreachable in a single pass.
- The script loops multiple passes (default up to `-MaxPasses 10`) from newest → oldest until a pass finds **no eligible comments** (older-than-cutoff, not excluded, not already processed). Then it stops and prints “No more eligible comments to delete (age + exclusions).”
- Checkpoint/resume stores the pass number and pagination cursor so you can resume mid-pass safely; each new pass restarts from the newest comments.
- Excluded subreddits and newer-than-cutoff comments are intentionally left; they still occupy slots in the newest ~1k window, so heavy exclusions or a lot of recent comments can prevent very old comments from ever becoming reachable.
- Opt-in retries: use `-RetryFailures` to avoid marking failed deletes as processed so they are retried on later passes. (Default behavior marks failures processed to avoid looping.)

---

## 11) Scope and limits

- ✅ Your comments
- ❌ Posts
- ❌ Other users’ content
- ❌ Votes, moderation, settings
