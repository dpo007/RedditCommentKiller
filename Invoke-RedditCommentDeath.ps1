<#
.SYNOPSIS
Deletes your own Reddit comments older than a chosen age, optionally overwriting them first.

.DESCRIPTION
PowerShell 7 script that authenticates to Reddit using a script app (personal use) via the resource owner password flow. It scans your comments, overwrites them for privacy (optional), and deletes them while respecting rate limits and offering resume/retry and reporting.

.PARAMETER ClientId
Reddit app client_id (personal use script app).

.PARAMETER ClientSecret
Reddit app client_secret.

.PARAMETER Username
Reddit username to authenticate and target.

.PARAMETER Password
Reddit account password as a SecureString. Converted to plain text only for the token request.

.PARAMETER UserAgent
User-Agent string Reddit requires (e.g. "platform:app:v1 (by /u/yourname)"). If not provided, automatically generated from your username.

.PARAMETER DaysOld
Delete comments older than this many days.

.PARAMETER SkipOverwrite
Skip the overwrite phase and delete comments without modifying their text first (default behavior is to overwrite unless this switch is used).

.PARAMETER OverwriteMode
Controls overwrite text selection: RotatePhrases, RandomJunk, or FixedText.

.PARAMETER FixedOverwriteText
Text used when OverwriteMode is FixedText.

.PARAMETER TwoPassProbability
Probability (0..1) that a given comment will use a two-pass overwrite (edit A -> wait -> edit B -> wait -> delete). Selection is stable per comment based on fullname and a local salt.

.PARAMETER TwoPassSaltPath
Path to a local salt file used to make two-pass selection stable across runs. If not provided, it is derived from ResumePath using the same base name.

.PARAMETER EditDelaySecondsMin
Minimum seconds to wait between edit and delete of a single comment.

.PARAMETER EditDelaySecondsMax
Maximum seconds to wait between edit and delete of a single comment.

.PARAMETER BetweenItemsDelayMin
Minimum seconds to wait between operations across comments.

.PARAMETER BetweenItemsDelayMax
Maximum seconds to wait between operations across comments.

.PARAMETER BatchSize
Number of comments to process before pausing for BatchCooldownSeconds.

.PARAMETER BatchCooldownSeconds
Seconds to pause after each batch to stay under rate limits.

.PARAMETER ResumePath
Path to checkpoint JSON for resuming.

.PARAMETER ProcessedLogPath
Path to an append-only log file containing processed fullnames (one per line). If not provided, it is derived from ResumePath using the same base name.

.PARAMETER ReportPath
CSV report output path.

.PARAMETER DryRun
List actions without performing edits or deletes.

.PARAMETER VerboseLogging
Emit extra diagnostic output.

.EXAMPLE
./Invoke-RedditCommentDeath.ps1 -ClientId abc -ClientSecret def -Username myuser -Password (Read-Host "Password" -AsSecureString) -DaysOld 90

.EXAMPLE
./Invoke-RedditCommentDeath.ps1 -ClientId abc -ClientSecret def -Username myuser -Password (Read-Host "Password" -AsSecureString) -DaysOld 30 -OverwriteMode FixedText -FixedOverwriteText "[deleted]" -UserAgent "custom:app:v1 (by /u/myuser)"

.EXAMPLE
./Invoke-RedditCommentDeath.ps1 -ClientId abc -ClientSecret def -Username myuser -Password (Read-Host "Password" -AsSecureString) -DaysOld 14 -SkipOverwrite
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [SecureString]$Password,

    [string]$UserAgent,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 5000)]
    [int]$DaysOld,

    [ValidateRange(0, 720)]
    [int]$SafetyHours = 0,

    [switch]$SkipOverwrite,

    [switch]$EnableMostlyProcessedStop,

    [ValidateRange(1, 100)]
    [int]$MostlyProcessedConsecutivePages = 3,

    [ValidateRange(0.0, 1.0)]
    [double]$MostlyProcessedRatioThreshold = 0.02,

    [ValidateRange(0, 1000)]
    [int]$MostlyProcessedMaxUnprocessedPerPage = 2,

    [ValidateSet('RotatePhrases', 'RandomJunk', 'FixedText')]
    [string]$OverwriteMode = 'RotatePhrases',

    [string]$FixedOverwriteText = '[deleted]',

    [ValidateRange(0.0, 1.0)]
    [double]$TwoPassProbability = 0.0,

    [ValidateRange(1, 86400)]
    [int]$EditDelaySecondsMin = 10,

    [ValidateRange(1, 86400)]
    [int]$EditDelaySecondsMax = 30,

    [ValidateRange(1, 86400)]
    [int]$BetweenItemsDelayMin = 2,

    [ValidateRange(1, 86400)]
    [int]$BetweenItemsDelayMax = 5,

    [ValidateRange(1, 1000)]
    [int]$BatchSize = 100,

    [ValidateRange(1, 86400)]
    [int]$BatchCooldownSeconds = 600,

    [string]$ResumePath = './reddit_cleanup_state.json',

    [string]$ProcessedLogPath,

    [string]$TwoPassSaltPath,

    [string]$ReportPath = './reddit_cleanup_report.csv',

    [switch]$DryRun,

    [switch]$VerboseLogging
)

# Validate delay range parameters to ensure min <= max
if ($EditDelaySecondsMax -lt $EditDelaySecondsMin) {
    throw "EditDelaySecondsMax must be >= EditDelaySecondsMin"
}

if ($BetweenItemsDelayMax -lt $BetweenItemsDelayMin) {
    throw "BetweenItemsDelayMax must be >= BetweenItemsDelayMin"
}

# Derive processed log path from ResumePath unless explicitly provided.
# Example: ./reddit_cleanup_state.json -> ./reddit_cleanup_state.processed_ids.log
if ([string]::IsNullOrWhiteSpace($ProcessedLogPath)) {
    $resumeDir = Split-Path -Parent $ResumePath
    $resumeLeaf = Split-Path -Leaf $ResumePath
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($resumeLeaf)
    if ([string]::IsNullOrWhiteSpace($resumeDir)) { $resumeDir = '.' }
    $ProcessedLogPath = Join-Path -Path $resumeDir -ChildPath ("$baseName.processed_ids.log")
}

# Derive two-pass salt path from ResumePath unless explicitly provided.
# Example: ./reddit_cleanup_state.json -> ./reddit_cleanup_state.two_pass_salt.txt
if ([string]::IsNullOrWhiteSpace($TwoPassSaltPath)) {
    $resumeDir = Split-Path -Parent $ResumePath
    $resumeLeaf = Split-Path -Leaf $ResumePath
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($resumeLeaf)
    if ([string]::IsNullOrWhiteSpace($resumeDir)) { $resumeDir = '.' }
    $TwoPassSaltPath = Join-Path -Path $resumeDir -ChildPath ("$baseName.two_pass_salt.txt")
}

# Auto-generate UserAgent if not provided (Reddit API requirement)
if ([string]::IsNullOrWhiteSpace($UserAgent)) {
    $platform = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } elseif ($IsLinux) { 'linux' } else { 'unknown' }
    $UserAgent = "${platform}:RedditCommentKiller:v1.0 (by /u/$Username)"
    if ($VerboseLogging) { Write-Verbose "Generated UserAgent: $UserAgent" }
}

# Determine whether overwrite phase should run (default true unless -SkipOverwrite is provided)
$OverwriteEnabled = -not $SkipOverwrite

function ConvertFrom-SecureStringPlain {
    <#
    .SYNOPSIS
    Securely converts SecureString to plain text with proper memory cleanup.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Secure
    )
    # Convert SecureString to BSTR (unmanaged memory)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        # Extract the plain text from unmanaged memory
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        # Always zero and free unmanaged memory for security
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Get-OrCreateTwoPassSalt {
    <#
    .SYNOPSIS
    Loads a stable local salt for two-pass selection, creating it if missing.
    #>
    if (Test-Path $TwoPassSaltPath) {
        $existing = (Get-Content -Path $TwoPassSaltPath -ErrorAction SilentlyContinue | Select-Object -First 1)
        if (-not [string]::IsNullOrWhiteSpace($existing)) { return ([string]$existing).Trim() }
    }

    $dir = Split-Path -Parent $TwoPassSaltPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $bytes = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $salt = [Convert]::ToBase64String($bytes)
    $salt | Set-Content -Path $TwoPassSaltPath -Encoding UTF8
    return $salt
}

function Get-StableProbability {
    <#
    .SYNOPSIS
    Returns a deterministic pseudo-random value in [0,1) based on Id + Salt.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Salt
    )

    $hashInput = "$Id|$Salt"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($hashInput)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
    }
    finally {
        $sha.Dispose()
    }

    $u = [System.BitConverter]::ToUInt64($hash, 0)
    return ([double]$u / ([double][UInt64]::MaxValue + 1.0))
}

# Script-level variable to store OAuth token and expiration time
# This allows token reuse across API calls until expiration
$Script:TokenInfo = $null

# Minimum spacing between Reddit API calls (fallback for endpoints that omit rate-limit headers).
# Reddit's published free-access guidance is ~100 queries/minute (~0.6s per request).
$Script:RedditApiMinRequestIntervalSeconds = 0.6
$Script:RedditApiLastRequestAtUtc = $null

function Get-AccessToken {
    <#
    .SYNOPSIS
    Obtains OAuth access token using Reddit's resource owner password flow.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [string]$UserAgent
    )

    # Convert SecureString password to plain text (only used for this API call)
    $plainPassword = ConvertFrom-SecureStringPlain -Secure $Password

    # Reddit requires Basic authentication with client_id:client_secret
    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$ClientId`:$ClientSecret"))

    # OAuth2 password grant flow requires grant_type, username, and password
    $body = @{ grant_type = 'password'; username = $Username; password = $plainPassword }
    $headers = @{ 'User-Agent' = $UserAgent; Authorization = "Basic $basicAuth" }

    # Request access token from Reddit's OAuth endpoint
    $resp = Invoke-RestMethod -Method Post -Uri 'https://www.reddit.com/api/v1/access_token' -Headers $headers -Body $body -ErrorAction Stop

    # Calculate expiration time with 30-second buffer to ensure we refresh before actual expiry
    $expiresAt = (Get-Date).ToUniversalTime().AddSeconds([int]$resp.expires_in - 30)

    # Cache token information at script scope for reuse
    $Script:TokenInfo = [PSCustomObject]@{
        AccessToken = $resp.access_token
        TokenType   = $resp.token_type
        ExpiresAt   = $expiresAt
    }
    if ($VerboseLogging) { Write-Verbose "Obtained token, expires at $($expiresAt.ToString('u'))" }
}

function Confirm-AccessToken {
    <#
    .SYNOPSIS
    Ensures a valid access token exists, refreshing if expired or missing.
    #>
    # Check if token is missing or expired; if so, obtain a new one
    if (-not $Script:TokenInfo -or (Get-Date).ToUniversalTime() -gt $Script:TokenInfo.ExpiresAt) {
        Get-AccessToken -ClientId $ClientId -ClientSecret $ClientSecret -Username $Username -Password $Password -UserAgent $UserAgent
    }
}

function Get-RandomDelay {
    <#
    .SYNOPSIS
    Generates a random delay to mimic human behavior and avoid rate limits.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$MinSeconds,
        [Parameter(Mandatory = $true)]
        [int]$MaxSeconds
    )
    # If max <= min, just return min (no randomization possible)
    if ($MaxSeconds -le $MinSeconds) { return $MinSeconds }
    # Get-Random's -Maximum is exclusive, so add 1 to include MaxSeconds
    Get-Random -Minimum $MinSeconds -Maximum ($MaxSeconds + 1)
}

function Get-OverwriteText {
    <#
    .SYNOPSIS
    Generates overwrite text based on selected mode for privacy protection.
    .DESCRIPTION
    Provides three methods: rotating neutral phrases, random junk text, or fixed text.
    Overwriting before deletion helps prevent data recovery from Reddit's archives.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )
    # Collection of innocuous phrases to replace comment content
    $phrases = @(
        'Nothing to see here.',
        'Content removed.',
        'Redacted by author.',
        'Moved on from this.',
        'Cleaning up old posts.',
        'Comment cleared.',
        'Pruned for privacy.',
        'Edited.',
        'Removed by user.',
        'Cleared out.',
        'Tidying history.',
        'No longer available.',
        'Deleted content.',
        'This comment is gone.',
        'Intentional removal.',
        'Nothing left here.',
        'Purged.',
        'Archived and removed.',
        'Obsolete comment.',
        'Clean slate.'
    )

    switch ($Mode) {
        'RotatePhrases' {
            # Select a random phrase from the collection
            return Get-Random -InputObject $phrases
        }
        'RandomJunk' {
            # Generate random alphanumeric + punctuation string
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:!?()-_=+[]{}<>/\\@#$%'
            $len = Get-Random -Minimum 20 -Maximum 121
            # Join random characters into a string of random length
            -join (1..$len | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
        }
        'FixedText' {
            # Use user-specified text
            return $FixedOverwriteText
        }
        default {
            # Fallback to standard deleted marker
            return '[deleted]'
        }
    }
}

function Invoke-RedditApi {
    <#
    .SYNOPSIS
    Wrapper for Reddit API calls with automatic retry, rate-limit handling, and token refresh.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [hashtable]$Body,
        [hashtable]$Query,
        [switch]$IsWrite,
        [switch]$AllowNonJsonResponse,
        [string]$Context
    )

    # Ensure we have a valid access token before making API calls
    Confirm-AccessToken

    # Retry configuration for transient failures
    $maxAttempts = 5
    $attempt = 0
    $backoff = 2  # Initial backoff in seconds, doubles on each retry
    $refreshedOn401 = $false

    while ($attempt -lt $maxAttempts) {
        $attempt++

        # Enforce a minimum delay between API calls (prevents tight loops when rate-limit headers are missing/inconsistent).
        if ($null -ne $Script:RedditApiLastRequestAtUtc -and $Script:RedditApiMinRequestIntervalSeconds -gt 0) {
            $nowUtc = [DateTimeOffset]::UtcNow
            $minInterval = [TimeSpan]::FromSeconds([double]$Script:RedditApiMinRequestIntervalSeconds)
            $elapsed = $nowUtc - $Script:RedditApiLastRequestAtUtc
            if ($elapsed -lt $minInterval) {
                $sleepMs = [int][math]::Ceiling(($minInterval - $elapsed).TotalMilliseconds)
                if ($sleepMs -gt 0) {
                    Start-Sleep -Milliseconds $sleepMs
                }
            }
        }

        # Build OAuth bearer token header (required for all authenticated Reddit API calls)
        $headers = @{ 'Authorization' = "bearer $($Script:TokenInfo.AccessToken)"; 'User-Agent' = $UserAgent }

        # Prepare request parameters; ResponseHeadersVariable captures rate-limit headers
        $params = @{ Method = $Method; Uri = $Uri; Headers = $headers; ErrorAction = 'Stop'; ResponseHeadersVariable = 'respHeaders' }
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = 'application/x-www-form-urlencoded'
        }

        # Build query string with proper URL encoding if query parameters provided
        if ($Query) {
            $qs = ($Query.GetEnumerator() | ForEach-Object {
                    "{0}={1}" -f [uri]::EscapeDataString($_.Key),
                    [uri]::EscapeDataString([string]$_.Value)
                }) -join '&'

            if ($qs) {
                $params.Uri = "$Uri?$qs"
            }
            else {
                $params.Uri = $Uri
            }
        }

        try {
            # Track request start time to maintain minimum spacing even when requests fail/retry.
            $Script:RedditApiLastRequestAtUtc = [DateTimeOffset]::UtcNow

            # Execute the HTTP request
            $resp = Invoke-WebRequest @params
            $content = $null
            $rawContent = $resp.Content
            $parseError = $null

            if ($rawContent) {
                if (-not $AllowNonJsonResponse) {
                    try {
                        $content = $rawContent | ConvertFrom-Json -ErrorAction Stop
                    }
                    catch {
                        $parseError = $_
                    }

                    $hasBody = -not [string]::IsNullOrWhiteSpace([string]$rawContent)
                    if (($parseError -or ($null -eq $content -and $hasBody))) {
                        $snippetLength = [Math]::Min([int]$rawContent.Length, 500)
                        $snippet = $rawContent.Substring(0, $snippetLength)
                        $snippet = $snippet -replace "`r", '' -replace "`n", ' '
                        $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
                        $statusLabel = $resp.StatusCode
                        $errMsg = $parseError ? $parseError.Exception.Message : 'Content was not JSON.'
                        throw "Expected JSON response$ctx for $Method $Uri but parsing failed (status $statusLabel). $errMsg Snippet: $snippet"
                    }
                }
                else {
                    # AllowNonJsonResponse is intended for endpoints that return empty/opaque bodies, not HTML defenses.
                    if ($rawContent -match '<!DOCTYPE html|<html') {
                        throw "Unexpected HTML response from Reddit (possible auth/rate-limit/protection page)."
                    }
                    $content = $rawContent | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
            }

            if ($VerboseLogging) { Write-Verbose "API $Method $Uri status $($resp.StatusCode) attempt $attempt" }

            # Check Reddit's documented rate-limit headers (treat as authoritative when present)
            # x-ratelimit-used / x-ratelimit-remaining / x-ratelimit-reset (reset is seconds-until-reset)
            if ($respHeaders['x-ratelimit-remaining'] -and $respHeaders['x-ratelimit-reset']) {
                $remainingRaw = @($respHeaders['x-ratelimit-remaining']) | Select-Object -First 1
                $resetRaw = @($respHeaders['x-ratelimit-reset']) | Select-Object -First 1

                $remaining = 0.0
                $reset = 0.0
                $culture = [System.Globalization.CultureInfo]::InvariantCulture
                $styles = [System.Globalization.NumberStyles]::Float

                $parsedRemaining = [double]::TryParse([string]$remainingRaw, $styles, $culture, [ref]$remaining)
                $parsedReset = [double]::TryParse([string]$resetRaw, $styles, $culture, [ref]$reset)

                # Preemptively sleep when remaining is low to avoid 429s due to skew or bursts.
                if ($parsedRemaining -and $parsedReset -and $remaining -lt 3 -and $reset -gt 0) {
                    $sleepFor = [math]::Ceiling($reset)
                    Write-Warning "Rate limit low (remaining=$remaining); sleeping $sleepFor seconds"
                    Start-Sleep -Seconds $sleepFor
                }
            }

            # Return both parsed data and headers for caller inspection
            return [PSCustomObject]@{ Data = $content; Headers = $respHeaders }
        }
        catch {
            $ex = $_.Exception
            $resp = $null
            $status = $null
            $retryAfterSeconds = $null

            # Safely extract response + status code (Response can be $null for DNS/TLS/network failures)
            try { $resp = $ex.Response } catch { $resp = $null }
            if ($resp) {
                try {
                    if ($resp.PSObject.Properties.Match('StatusCode').Count -gt 0 -and $null -ne $resp.StatusCode) {
                        # HttpResponseMessage.StatusCode is an enum; int cast is fine
                        $status = [int]$resp.StatusCode
                    }
                    elseif ($resp.StatusCode -and $null -ne $resp.StatusCode.value__) {
                        # Some response types expose the underlying int on value__
                        $status = [int]$resp.StatusCode.value__
                    }
                }
                catch {
                    $status = $null
                }

                # Safely extract Retry-After (may be absent or an HTTP date)
                try {
                    $raRaw = $null

                    if ($resp.PSObject.Properties.Match('Headers').Count -gt 0 -and $resp.Headers) {
                        # HttpResponseMessage: Headers can expose RetryAfter as a structured value
                        if ($resp.Headers.PSObject.Properties.Match('RetryAfter').Count -gt 0 -and $resp.Headers.RetryAfter) {
                            if ($resp.Headers.RetryAfter.Delta) {
                                $retryAfterSeconds = [int][math]::Ceiling($resp.Headers.RetryAfter.Delta.TotalSeconds)
                            }
                            elseif ($resp.Headers.RetryAfter.Date) {
                                $until = $resp.Headers.RetryAfter.Date.UtcDateTime - (Get-Date).ToUniversalTime()
                                $retryAfterSeconds = [int][math]::Ceiling($until.TotalSeconds)
                            }
                        }
                        elseif ($resp.Headers.PSObject.Methods.Match('GetValues').Count -gt 0) {
                            $raRaw = @($resp.Headers.GetValues('Retry-After')) | Select-Object -First 1
                        }
                        else {
                            $raRaw = $resp.Headers['Retry-After']
                        }
                    }

                    if (-not $retryAfterSeconds -and $raRaw) {
                        $tmp = 0
                        if ([int]::TryParse([string]$raRaw, [ref]$tmp)) {
                            $retryAfterSeconds = $tmp
                        }
                        else {
                            $date = $null
                            if ([DateTimeOffset]::TryParse([string]$raRaw, [ref]$date)) {
                                $until = $date.UtcDateTime - (Get-Date).ToUniversalTime()
                                $retryAfterSeconds = [int][math]::Ceiling($until.TotalSeconds)
                            }
                        }
                    }
                }
                catch {
                    $retryAfterSeconds = $null
                }
            }

            # 401: token can expire or be invalidated mid-run; refresh once and retry
            if ($status -eq 401 -and -not $refreshedOn401 -and $attempt -lt $maxAttempts) {
                $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
                Write-Warning "API call returned 401 Unauthorized$ctx; refreshing token and retrying once."
                Get-AccessToken -ClientId $ClientId -ClientSecret $ClientSecret -Username $Username -Password $Password -UserAgent $UserAgent
                $refreshedOn401 = $true
                continue
            }

            # Retry policy
            $shouldRetry = $false

            if ($null -ne $status) {
                # Retry on rate-limit (429) or server errors (5xx)
                $shouldRetry = $status -eq 429 -or ($status -ge 500 -and $status -lt 600)
            }
            else {
                # Transient non-HTTP failures (DNS/TLS/network/timeouts) can have no Response
                $shouldRetry = (
                    $ex -is [Microsoft.PowerShell.Commands.HttpResponseException] -or
                    $ex -is [System.Net.Http.HttpRequestException] -or
                    $ex -is [System.Net.WebException] -or
                    $ex -is [System.TimeoutException] -or
                    ($ex.InnerException -and (
                        $ex.InnerException -is [System.Net.Http.HttpRequestException] -or
                        $ex.InnerException -is [System.Net.WebException] -or
                        $ex.InnerException -is [System.Net.Sockets.SocketException] -or
                        $ex.InnerException -is [System.TimeoutException]
                    ))
                )
            }

            if ($shouldRetry -and $attempt -lt $maxAttempts) {
                $delay = $backoff
                if ($null -ne $retryAfterSeconds) {
                    $delay = [Math]::Max([int]$retryAfterSeconds, 1)
                }

                $statusLabel = ($null -ne $status) ? $status : 'no-http-response'
                $reason = ($null -ne $status) ? "status $statusLabel" : "non-HTTP failure: $($ex.Message)"
                $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
                Write-Warning "API call failed$ctx ($reason); retrying in $delay s (attempt $attempt of $maxAttempts)"
                Start-Sleep -Seconds $delay

                # Double backoff for next retry, capped at 60 seconds
                $backoff = [Math]::Min($backoff * 2, 60)
                continue
            }

            throw
        }
    }
}

function Get-CommentsPage {
    <#
    .SYNOPSIS
    Fetches a page of user comments using Reddit's listing pagination.
    #>
    param(
        [string]$AfterToken
    )
    # Reddit's listing API uses 'limit' to control page size (max 100)
    $query = @{ limit = 100 }

    # 'after' token is used for pagination (Reddit's cursor-based paging)
    if ($AfterToken) { $query.after = $AfterToken }

    $uri = "https://oauth.reddit.com/user/$Username/comments"
    Invoke-RedditApi -Method Get -Uri $uri -Query $query
}

function Save-Checkpoint {
    <#
    .SYNOPSIS
    Saves current processing state to enable resume after interruption.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $State
    )
    # Serialize state to JSON
    $json = $State | ConvertTo-Json -Depth 5

    # Ensure parent directory exists
    $dir = Split-Path -Parent $ResumePath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Write checkpoint file (includes pagination token and processed comment IDs)
    $json | Set-Content -Path $ResumePath -Encoding UTF8
}

function Initialize-ProcessedLog {
    <#
    .SYNOPSIS
    Ensures the processed-id log file exists (append-only).
    #>
    $dir = Split-Path -Parent $ProcessedLogPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (-not (Test-Path $ProcessedLogPath)) {
        New-Item -ItemType File -Path $ProcessedLogPath -Force | Out-Null
    }
}

function Import-ProcessedLog {
    <#
    .SYNOPSIS
    Loads processed IDs from the append-only log into a HashSet.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$Set
    )

    if (-not (Test-Path $ProcessedLogPath)) { return }

    foreach ($line in (Get-Content -Path $ProcessedLogPath -ErrorAction SilentlyContinue)) {
        $id = [string]$line
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $Set.Add($id.Trim()) | Out-Null
    }
}

function Add-ProcessedIds {
    <#
    .SYNOPSIS
    Appends one or more processed IDs to the processed-id log efficiently.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Ids
    )
    if (-not $Ids -or $Ids.Count -eq 0) { return }

    Initialize-ProcessedLog

    $enc = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::AppendAllLines($ProcessedLogPath, $Ids, $enc)
}

function Import-Checkpoint {
    <#
    .SYNOPSIS
    Loads previous processing state if available, otherwise returns fresh state.
    #>
    if (Test-Path $ResumePath) {
        try {
            # Attempt to parse checkpoint JSON
            $loaded = Get-Content -Path $ResumePath -Raw | ConvertFrom-Json -ErrorAction Stop

            # Backward-compat: older checkpoints stored a large `processed` array.
            # Newer checkpoints only store `after`.
            if ($null -eq $loaded.processed) {
                $loaded | Add-Member -NotePropertyName processed -NotePropertyValue @() -Force
            }
            if ($null -eq $loaded.after) {
                $loaded | Add-Member -NotePropertyName after -NotePropertyValue $null -Force
            }
            return $loaded
        }
        catch {
            # If checkpoint is corrupted, warn and start fresh
            Write-Warning "Failed to parse checkpoint; starting fresh."
        }
    }
    # Return empty state (no pagination token, no processed items)
    return [PSCustomObject]@{ after = $null; processed = @() }
}

function Initialize-Report {
    <#
    .SYNOPSIS
    Initializes CSV report file with headers if it doesn't exist.
    #>
    # Skip if report already exists (allows appending to existing reports)
    if (Test-Path $ReportPath) { return }

    # Create CSV with column headers
    [PSCustomObject]@{ created_utc = ''; permalink = ''; subreddit = ''; fullname = ''; action = ''; status = ''; error = '' } | Export-Csv -Path $ReportPath -NoTypeInformation
}

function Add-ReportRow {
    <#
    .SYNOPSIS
    Appends a single row to the CSV report.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Row
    )
    # Append without re-writing headers
    $Row | Export-Csv -Path $ReportPath -NoTypeInformation -Append
}

# Calculate cutoff in UTC: comments older than this will be processed
# Using UTC end-to-end prevents timezone/DST boundary misclassification.
$cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $DaysOld)

# Optional safety margin shifts the effective cutoff older to guard against clock/math mistakes
$effectiveCutoffUtc = $cutoffUtc.AddHours(-1 * $SafetyHours)

# Load checkpoint to resume from previous run if interrupted
$state = Import-Checkpoint

# Ensure processed-id log exists and load it into a HashSet for O(1) lookups
Initialize-ProcessedLog

$processedSet = [System.Collections.Generic.HashSet[string]]::new()
Import-ProcessedLog -Set $processedSet

# Migrate any legacy `processed` ids stored in the checkpoint into the append-only log (Option B)
if ($state.processed -and $state.processed.Count -gt 0) {
    $toAppend = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $state.processed) {
        $id = [string]$p
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $id = $id.Trim()
        if ($processedSet.Add($id)) {
            $toAppend.Add($id)
        }
    }

    if ($toAppend.Count -gt 0) {
        Add-ProcessedIds -Ids $toAppend.ToArray()
        Write-Host "Migrated $($toAppend.Count) legacy processed IDs into $ProcessedLogPath" -ForegroundColor Yellow
    }
}

# Two-pass overwrite selection uses a stable local salt.
$twoPassSalt = $null
if ($TwoPassProbability -gt 0) {
    $twoPassSalt = Get-OrCreateTwoPassSalt
}

# Ensure CSV report exists with headers
Initialize-Report

# Track processing statistics for final summary
$summary = [PSCustomObject]@{ scanned = 0; matched = 0; edited = 0; deleted = 0; failures = 0 }
$batchCount = 0
$consecutiveMostlyProcessedPages = 0

# Resume from saved pagination token if available
$after = $state.after
$pastCutoffZone = $false

if ($SafetyHours -gt 0) {
    Write-Host "Scanning comments older than $DaysOld days with safety margin $SafetyHours h (effective cutoff UTC $($effectiveCutoffUtc.ToString('u')); raw cutoff $($cutoffUtc.ToString('u')))" -ForegroundColor Cyan
}
else {
    Write-Host "Scanning comments older than $DaysOld days (cutoff UTC $($effectiveCutoffUtc.ToString('u')))" -ForegroundColor Cyan
}

# Main pagination loop: iterate through all comment pages
while ($true) {
    # Fetch next page of comments using pagination token
    $page = Get-CommentsPage -AfterToken $after
    $data = $page.Data

    # Stop if no more data returned
    if (-not $data || -not $data.data.children) { break }

    $children = $data.data.children
    if (-not $children) { break }

    $pageOlderTotal = 0
    $pageOlderUnprocessed = 0

    # Process each comment in the current page
    foreach ($child in $children) {
        $comment = $child.data
        $summary.scanned++

        # Convert Unix timestamp to UTC DateTime for age comparison (Reddit timestamps are UTC)
        $createdUtc = [DateTimeOffset]::FromUnixTimeSeconds([long]$comment.created_utc).UtcDateTime

        # Extract comment identifiers and metadata
        $fullname = $comment.name  # Reddit's full thing ID (e.g., "t1_abc123")
        $permalink = "https://www.reddit.com$($comment.permalink)"
        $subreddit = $comment.subreddit

        # Listing is newest -> oldest. Skip newer-than-cutoff and keep paging until end.
        if (-not $pastCutoffZone) {
            if ($createdUtc -gt $effectiveCutoffUtc) { continue }
            # We have reached the cutoff zone; all remaining items are older.
            $pastCutoffZone = $true
        }

        # Once past the cutoff, track per-page older-item stats for stop-optimizations
        if ($pastCutoffZone) { $pageOlderTotal++ }

        # Skip if already processed in previous run (resume functionality)
        if ($processedSet.Contains($fullname)) { continue }

        $summary.matched++
        $actionDesc = "comment $fullname"

        # Honor -WhatIf parameter (CmdletBinding SupportsShouldProcess)
        if (-not $PSCmdlet.ShouldProcess($actionDesc, 'Process')) { continue }

        if ($pastCutoffZone) { $pageOlderUnprocessed++ }

        # Initialize tracking variables for this comment's processing
        $overwriteText = $null
        $editStatus = 'skipped'
        $deleteStatus = 'skipped'
        $errorMessage = ''
        $didWrite = $false  # Track if we performed a write operation

        # Stable-random selection for two-pass overwrite (deterministic across re-runs for you; unpredictable to outsiders)
        $doTwoPass = $false
        if ($OverwriteEnabled -and $TwoPassProbability -gt 0 -and $twoPassSalt) {
            $p = Get-StableProbability -Id $fullname -Salt $twoPassSalt
            if ($p -lt $TwoPassProbability) { $doTwoPass = $true }
        }

        # Overwrite phase: replace comment content for privacy before deletion (unless -SkipOverwrite)
        if ($OverwriteEnabled) {
            $overwriteText = Get-OverwriteText -Mode $OverwriteMode
            $didWrite = -not $DryRun

            if (-not $DryRun) {
                try {
                    # Reddit's editusertext endpoint requires thing_id and new text
                    $body = @{ api_type = 'json'; thing_id = $fullname; text = $overwriteText }
                    Invoke-RedditApi -Method Post -Uri 'https://oauth.reddit.com/api/editusertext' -Body $body -IsWrite -AllowNonJsonResponse -Context $fullname
                    $summary.edited++
                    $editStatus = $doTwoPass ? 'edited(1/2)' : 'edited'
                }
                catch {
                    # Continue to delete even if edit fails (e.g., archived/locked comments)
                    $errorMessage = "Edit failed: $($_.Exception.Message)"
                    Write-Warning "$fullname edit failed: $errorMessage"
                    $summary.failures++
                }
            }
            else {
                # Dry-run mode: simulate without actual API calls
                $editStatus = $doTwoPass ? 'dry-run(1/2)' : 'dry-run'
            }

            # Randomized delay between overwrite passes / before delete to appear more human
            $sleep = Get-RandomDelay -MinSeconds $EditDelaySecondsMin -MaxSeconds $EditDelaySecondsMax
            if ($sleep -gt 0) { Start-Sleep -Seconds $sleep }

            # Optional second overwrite pass for a stable-random subset of comments
            if ($doTwoPass) {
                # Try to ensure the second overwrite differs from the first (avoid accidental duplicates)
                $overwriteText2 = $null
                for ($i = 0; $i -lt 3; $i++) {
                    $candidate = Get-OverwriteText -Mode $OverwriteMode
                    if ($candidate -ne $overwriteText) { $overwriteText2 = $candidate; break }
                }
                if (-not $overwriteText2) { $overwriteText2 = Get-OverwriteText -Mode $OverwriteMode }

                if (-not $DryRun) {
                    try {
                        $body2 = @{ api_type = 'json'; thing_id = $fullname; text = $overwriteText2 }
                        Invoke-RedditApi -Method Post -Uri 'https://oauth.reddit.com/api/editusertext' -Body $body2 -IsWrite -AllowNonJsonResponse -Context $fullname
                        $summary.edited++
                        $editStatus = 'edited(2/2)'
                    }
                    catch {
                        $errorMessage = ($errorMessage ? ($errorMessage + ' | ') : '') + "Second edit failed: $($_.Exception.Message)"
                        Write-Warning "$fullname second edit failed: $($_.Exception.Message)"
                        $summary.failures++
                        $editStatus = 'edited(1/2)+fail(2/2)'
                    }
                }
                else {
                    $editStatus = 'dry-run(2/2)'
                }

                $sleep2 = Get-RandomDelay -MinSeconds $EditDelaySecondsMin -MaxSeconds $EditDelaySecondsMax
                if ($sleep2 -gt 0) { Start-Sleep -Seconds $sleep2 }
            }
        }

        # Deletion phase: remove comment from Reddit
        if (-not $DryRun) {
            try {
                # Reddit's del endpoint requires the thing's full name
                $body = @{ id = $fullname }
                Invoke-RedditApi -Method Post -Uri 'https://oauth.reddit.com/api/del' -Body $body -IsWrite -AllowNonJsonResponse -Context $fullname
                $summary.deleted++
                $deleteStatus = 'deleted'
            }
            catch {
                $errorMessage = "Delete failed: $($_.Exception.Message)"
                Write-Warning "$fullname delete failed: $errorMessage"
                $summary.failures++
            }
        }
        else {
            # Dry-run mode: log action without executing
            $deleteStatus = 'dry-run'
        }

        # Record this comment's processing result in CSV report
        Add-ReportRow ([PSCustomObject]@{
                created_utc = $createdUtc.ToString('u')
                permalink   = $permalink
                subreddit   = $subreddit
                fullname    = $fullname
                action      = $OverwriteEnabled ? ($doTwoPass ? '2xedit+delete' : 'edit+delete') : 'delete'
                status      = "$editStatus/$deleteStatus"
                error       = $errorMessage
            })

        # Mark as processed to avoid reprocessing on resume
        if ($processedSet.Add($fullname)) {
            Add-ProcessedIds -Ids @($fullname)
        }
        $batchCount++

        # Delay between items to avoid rate limiting and appear less bot-like
        $sleepBetween = Get-RandomDelay -MinSeconds $BetweenItemsDelayMin -MaxSeconds $BetweenItemsDelayMax

        # Enforce minimum 2-second delay for write operations (Reddit best practice)
        if ($sleepBetween -lt 2 -and $didWrite) { $sleepBetween = 2 }
        if ($sleepBetween -gt 0) { Start-Sleep -Seconds $sleepBetween }

        # Batch cooldown: pause after processing BatchSize items to stay well under rate limits
        if ($batchCount -ge $BatchSize) {
            Write-Host "Batch of $batchCount completed; cooling down for $BatchCooldownSeconds seconds" -ForegroundColor Yellow
            Start-Sleep -Seconds $BatchCooldownSeconds
            $batchCount = 0
        }

    }

    # Extract next page token from Reddit's response for pagination
    $after = $data.data.after

    $stopPaging = $false
    if ($pastCutoffZone -and $pageOlderTotal -gt 0) {
        if ($pageOlderUnprocessed -eq 0) {
            $stopPaging = $true
            if ($VerboseLogging) { Write-Verbose "Stopping: past cutoff and page older items already processed (total=$pageOlderTotal)." }
        }
        elseif ($EnableMostlyProcessedStop) {
            $ratio = $pageOlderUnprocessed / [double]$pageOlderTotal
            if ($pageOlderUnprocessed -le $MostlyProcessedMaxUnprocessedPerPage -and $ratio -le $MostlyProcessedRatioThreshold) {
                $consecutiveMostlyProcessedPages++
                if ($VerboseLogging) {
                    Write-Verbose ("Mostly-processed page {0}/{1} (older total={2}, unprocessed={3}, ratio={4:P2})" -f $consecutiveMostlyProcessedPages, $MostlyProcessedConsecutivePages, $pageOlderTotal, $pageOlderUnprocessed, $ratio)
                }
                if ($consecutiveMostlyProcessedPages -ge $MostlyProcessedConsecutivePages) {
                    $stopPaging = $true
                }
            }
            else {
                $consecutiveMostlyProcessedPages = 0
            }
        }
        else {
            $consecutiveMostlyProcessedPages = 0
        }
    }
    else {
        $consecutiveMostlyProcessedPages = 0
    }

    # Save checkpoint at page boundary using next-page cursor
    Save-Checkpoint -State ([PSCustomObject]@{ after = $after })

    if ($stopPaging) { break }

    # If no 'after' token, we've reached the end of the listing
    if (-not $after) { break }
}

# Final checkpoint save with complete processed list
Save-Checkpoint -State ([PSCustomObject]@{ after = $after })

Write-Host "Scan complete." -ForegroundColor Cyan
Write-Host "Scanned: $($summary.scanned) | Matched: $($summary.matched) | Edited: $($summary.edited) | Deleted: $($summary.deleted) | Failures: $($summary.failures)" -ForegroundColor Green
Write-Host "Report saved to $ReportPath" -ForegroundColor Green
Write-Host "Checkpoint saved to $ResumePath" -ForegroundColor Green
