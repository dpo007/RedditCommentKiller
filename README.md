# 🧹 Reddit Comment Killer (a.k.a. "Invoke-RedditCommentDeath") 💬🪓

A PowerShell 7 script that finds **your own** Reddit comments older than a chosen age, optionally **overwrites** them first, and then **deletes** them — with rate-limit friendliness, resume support, and a paper trail (CSV report).

It’s basically spring cleaning for your comment history. It runs using a session-derived token from your logged-in Reddit session. 🧽✨

**Auth note (important):** Session-derived token reuse only. Why not OAuth? Reddit is axing OAuth API access for regular users, so this script sticks to the session tokens you already have.

## ✅ What this is

- 🧩 A single-file PowerShell script: `Invoke-RedditCommentDeath.ps1`
- 🔐 Auth: session-derived token reuse (default)
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

- 🔑 **Auth:** session-derived token reuse (`-SessionAccessToken`), single-user only
- 🧑‍⚖️ **Identity verification:** verifies `/api/v1/me` before doing anything destructive.
- 🔁 **Resume support:** safe to stop/re-run; it won’t reprocess already handled comments.
- 🐢 **Rate-limit aware:** randomized delays + batching cooldowns + defensive retry logic.
- 🧪 **Dry runs:** see what would happen without changing anything.
- 📊 **CSV report output:** so future-you can answer “what did I do?” without guessing.
- 🚫 **Exclude subreddits:** optionally skip specific subreddits using `-ExcludedSubredditsFile` (one subreddit name per line).

## 🧾 Requirements

- 🐉 **PowerShell 7+** (the script declares `#requires -Version 7.0`)
- For auth: a session-derived access token from a logged-in Reddit session (passed securely via `-SessionAccessToken`).

## 🚀 Quick start (primary/default: session-derived)

1) Obtain a session-derived token from your logged-in Reddit session (treat as highly sensitive; do not log it).

2) Run a dry run first (seriously):

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90 `
  -DryRun
```

3) Run for real (default: overwrite + delete):

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90
```

### 🚫 Exclude specific subreddits

Create a text file (one subreddit per line):

```text
# excluded-subreddits.txt
AskReddit
r/SomeSub
/r/AnotherSub/
```

Then run:

```powershell
./Invoke-RedditCommentDeath.ps1 `
  -SessionAccessToken (Read-Host "Session token" -AsSecureString) `
  -DaysOld 90 `
  -ExcludedSubredditsFile "./excluded-subreddits.txt"
```

## 📚 Where the real docs live

For full setup, refresh-token instructions, overwrite modes, rate-limit knobs, resume files, and troubleshooting:

- 👉 See **[UserGuide.md](./UserGuide.md)**

(Yes, it’s longer. Yes, that’s on purpose. The alternative is you guessing at Reddit’s auth quirks by “vibes,” and nobody wants that.)

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

The Unlicense (public domain). ✅

See https://unlicense.org/

---

## 🕶️ Epilogue

> "No rules are broken. No alarms are triggered. Things simply… disappear."
