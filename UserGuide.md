# UserGuide.md — Reddit Comment Cleanup Script

This guide walks you through setting up and safely running the Reddit comment cleanup script.

**Auth note (important):**
The **primary and default authentication method** is **session-derived token reuse** (single-user).
OAuth is supported **only as a secondary fallback**, because Reddit OAuth app approval and long-term reliability can be inconsistent or unavailable for some users.

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
- Optional: `-Username`
  - If omitted, the script automatically adopts the authenticated username from `/api/v1/me`

### Dry run (run this first)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

### Real run (overwrite + delete)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90
```

---

## 3) Choose exactly ONE authentication mode

The script enforces **mutual exclusivity**.

- **SessionDerived (default)**
  Supply `-SessionAccessToken`

- **OAuth (secondary / fallback)**
  Supply `-ClientId`, `-ClientSecret`, and either `-Password` or `-RefreshToken`

---

## 4) Decide what gets deleted

Use `-DaysOld` to control the cutoff.

Examples:
- 90 days → `-DaysOld 90`
- 1 year → `-DaysOld 365`

Optional safety buffer:

```powershell
-SafetyHours 24
```

---

## 5) Overwrite behavior

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

## 6) Safe testing (Dry Run)

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

---

## 7) Run for real

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90
```

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

## 10) OAuth fallback (optional)

Only use if session-derived auth is unavailable.

Includes:
- App creation
- Password or refresh-token auth
- One-time refresh token exchange

---

## 11) Scope and limits

- ✅ Your comments
- ❌ Posts
- ❌ Other users’ content
- ❌ Votes, moderation, settings
