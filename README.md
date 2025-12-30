# 🧹 Reddit Comment Killer (a.k.a. "Invoke-RedditCommentDeath") 💬🪓

A PowerShell 7 script that finds **your own** Reddit comments older than a chosen age, optionally **overwrites** them first, and then **deletes** them — with rate-limit friendliness, resume support, and a paper trail (CSV report).

It’s basically spring cleaning for your comment history, except the broom is an OAuth token and the dust bunnies are `t1_` fullnames. 🧽✨

## ✅ What this is

- 🧩 A single-file PowerShell script: `Invoke-RedditCommentDeath.ps1`
- 🔐 Uses Reddit OAuth (script app) to authenticate as you
- 🔎 Scans your user comment listing (newest → oldest)
- ⏳ Processes comments older than `-DaysOld`
- ✍️🧼 Optionally overwrites comment text (default) before deleting
- 🧾 Produces:
  - a resume checkpoint JSON
  - an append-only processed-id log
  - a CSV report of actions taken

## ❌ What this is *not*

- 💣 Not a Reddit “nuke everything” button.
- 📝 Not a post/submission deleter.
- 🙅 Not for other users’ content.
- 🧠 Not guaranteed to outsmart every archive, cache, screenshot, or quote-tweet from 2017.

## 🛡️ Features (aka “the safety rails”)

- 🔑 **Two auth modes (exactly one):**
  - password grant (`-Password`) for quick runs
  - refresh-token grant (`-RefreshToken`) for repeatable runs without typing your password
- 🧑‍⚖️ **Identity verification:** confirms `/api/v1/me` matches `-Username` before doing anything destructive.
- 🔁 **Resume support:** safe to stop/re-run; it won’t reprocess already handled comments.
- 🐢 **Rate-limit aware:** randomized delays + batching cooldowns + defensive retry logic.
- 🧪 **Dry runs:** see what would happen without changing anything.
- 📊 **CSV report output:** so future-you can answer “what did I do?” without guessing.

## 📦 Requirements

- 🐉 **PowerShell 7+** (the script declares `#requires -Version 7.0`)
- 🧾 A Reddit **script app** (client id + secret)
- 🧭 Scopes appropriate to what you plan to do:
  - listing: `identity,history,read`
  - overwriting: `edit`
  - deleting: handled by the authenticated API flow used by the script

## 🚀 Quick start (the basics)

1) Create a Reddit “script” app to get a **Client ID** and **Client Secret**:
- https://www.reddit.com/prefs/apps

2) Run a dry run first (seriously):

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

3) Run for real (default: overwrite + delete):

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -Password (Read-Host "Password" -AsSecureString) `
  -DaysOld 90
```

4) Prefer a refresh token for repeat runs:

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -ClientId "YOUR_ID" `
  -ClientSecret "YOUR_SECRET" `
  -Username "YOUR_USERNAME" `
  -RefreshToken (Read-Host "Refresh Token" -AsSecureString) `
  -DaysOld 90
```

## 📚 Where the real docs live

For full setup, refresh-token instructions, overwrite modes, rate-limit knobs, resume files, and troubleshooting:

- 👉 See **`UserGuide.md`**

(Yes, it’s longer. Yes, that’s on purpose. The alternative is you learning OAuth by “vibes,” and nobody wants that.)

## 🧾 Outputs

By default the script creates these files alongside where you run it:

- `./reddit_cleanup_state.json` (resume checkpoint)
- `./reddit_cleanup_state.processed_ids.log` (append-only processed fullnames)
- `./reddit_cleanup_report.csv` (what happened)

Paths can be overridden via parameters.

## ⚠️ A small, friendly warning

This script can delete a lot of your comment history very quickly.

- 🧪 Use `-DryRun` first.
- 🧯 Consider using `-SafetyHours` if you’re worried about “cutoff boundary” mistakes.
- 🐢 Reddit rate limits and anti-abuse systems exist; the defaults are intentionally conservative.

## 📝 License

Not specified (yet). If you want, tell me what license you prefer (MIT/Apache-2.0/GPL-3.0/etc.) and I can add it.
