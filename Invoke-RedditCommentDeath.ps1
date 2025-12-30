<#
.SYNOPSIS
Deletes your own Reddit comments older than a chosen age, optionally overwriting them first.

.DESCRIPTION
PowerShell 7 script that authenticates to Reddit using a script app (personal use) via the resource owner password flow. It scans your comments, overwrites them for privacy (optional), and deletes them while respecting rate limits and offering resume/retry and reporting.

.PARAMETER ClientId
Reddit app client_id (personal use script app). Required when -AuthMode OAuth.

.PARAMETER ClientSecret
Reddit app client_secret. Required when -AuthMode OAuth.

.PARAMETER Username
Reddit username to authenticate and target.

.PARAMETER AuthMode
Selects the authentication provider: OAuth (default) or SessionDerived (session-derived token reuse).

.PARAMETER Password
Reddit account password as a SecureString. Converted to plain text only for the token request (OAuth mode only).

Mutually exclusive with -RefreshToken.

.PARAMETER RefreshToken
OAuth refresh token as a SecureString. If provided, the script will use the refresh-token grant instead of the password grant (OAuth mode only).

Mutually exclusive with -Password.

.PARAMETER SessionAccessToken
Session-derived access token as a SecureString (e.g., bearer-style token derived from a signed-in browser session). Never logged; kept in-memory.

.PARAMETER SessionApiBaseUri
API base URI to use when -AuthMode SessionDerived (default: https://oauth.reddit.com).

.PARAMETER SessionAuthorizationScheme
Authorization scheme/prefix to pair with the session-derived token (default: bearer).

.PARAMETER SessionSecretName
Optional label/secret-name metadata for the session-derived token source (not stored). Useful if integrating with an OS-protected secret store externally.

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

.PARAMETER ExcludedSubredditsFile
Optional path to a text file containing subreddit names to exclude (one per line).
If provided, comments in these subreddits will be skipped (not edited/deleted/reported).
Blank lines are ignored. Lines starting with # are ignored as comments.
Entries may be formatted as "subname", "r/subname", or "/r/subname".

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

#requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'SessionDerived')]
param(
    # Common
    [Parameter(ParameterSetName = 'SessionDerived')]
    [Parameter(ParameterSetName = 'OAuthPassword')]
    [Parameter(ParameterSetName = 'OAuthRefresh')]
    [string]$Username,

    [Parameter(ParameterSetName = 'SessionDerived')]
    [Parameter(ParameterSetName = 'OAuthPassword')]
    [Parameter(ParameterSetName = 'OAuthRefresh')]
    [ValidateSet('SessionDerived', 'OAuth')]
    [string]$AuthMode,

    [Parameter(ParameterSetName = 'SessionDerived')]
    [Parameter(ParameterSetName = 'OAuthPassword')]
    [Parameter(ParameterSetName = 'OAuthRefresh')]
    [string]$UserAgent,

    [Parameter(Mandatory = $true, ParameterSetName = 'SessionDerived')]
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthPassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthRefresh')]
    [ValidateRange(1, 5000)]
    [int]$DaysOld,

    # Session-derived mode
    [Parameter(Mandatory = $true, ParameterSetName = 'SessionDerived')]
    [SecureString]$SessionAccessToken,

    [Parameter(ParameterSetName = 'SessionDerived')]
    [string]$SessionApiBaseUri = 'https://oauth.reddit.com',

    [Parameter(ParameterSetName = 'SessionDerived')]
    [string]$SessionAuthorizationScheme = 'bearer',

    [Parameter(ParameterSetName = 'SessionDerived')]
    [string]$SessionSecretName,

    # OAuth shared
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthPassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthRefresh')]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthPassword')]
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthRefresh')]
    [string]$ClientSecret,

    # OAuth: password grant
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthPassword')]
    [SecureString]$Password,

    # OAuth: refresh-token grant
    [Parameter(Mandatory = $true, ParameterSetName = 'OAuthRefresh')]
    [SecureString]$RefreshToken,

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

    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ExcludedSubredditsFile,

    [string]$TwoPassSaltPath,

    [string]$ReportPath = './reddit_cleanup_report.csv',

    [switch]$DryRun,

    [switch]$VerboseLogging
)

# Normalize AuthMode based on selected parameter set and enforce consistency
switch ($PSCmdlet.ParameterSetName) {
    'SessionDerived' {
        if ([string]::IsNullOrWhiteSpace($AuthMode)) { $AuthMode = 'SessionDerived' }
        if (-not [string]::Equals($AuthMode, 'SessionDerived', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "AuthMode '$AuthMode' is not allowed in the SessionDerived parameter set."
        }
    }
    'OAuthPassword' {
        if ([string]::IsNullOrWhiteSpace($AuthMode)) { $AuthMode = 'OAuth' }
        if (-not [string]::Equals($AuthMode, 'OAuth', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "AuthMode '$AuthMode' is not allowed in the OAuthPassword parameter set."
        }
    }
    'OAuthRefresh' {
        if ([string]::IsNullOrWhiteSpace($AuthMode)) { $AuthMode = 'OAuth' }
        if (-not [string]::Equals($AuthMode, 'OAuth', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "AuthMode '$AuthMode' is not allowed in the OAuthRefresh parameter set."
        }
    }
    default {
        throw "Unknown parameter set '$($PSCmdlet.ParameterSetName)'."
    }
}

$usingOAuth = [string]::Equals($AuthMode, 'OAuth', [System.StringComparison]::OrdinalIgnoreCase)
$usingSessionDerived = -not $usingOAuth

$hasPassword = $PSBoundParameters.ContainsKey('Password') -and $null -ne $Password
$hasRefreshToken = $PSBoundParameters.ContainsKey('RefreshToken') -and $null -ne $RefreshToken
$hasSessionToken = $PSBoundParameters.ContainsKey('SessionAccessToken') -and $null -ne $SessionAccessToken

# Extra guardrails for parameter misuse across sets (PowerShell already enforces most conflicts)
if ($usingSessionDerived) {
    if (-not $hasSessionToken) { throw "SessionDerived mode requires -SessionAccessToken (SecureString)." }
    if ([string]::IsNullOrWhiteSpace($SessionApiBaseUri)) { throw "-SessionApiBaseUri cannot be empty when -AuthMode SessionDerived." }
    if ([string]::IsNullOrWhiteSpace($SessionAuthorizationScheme)) { throw "-SessionAuthorizationScheme cannot be empty when -AuthMode SessionDerived." }
    if ($hasPassword -or $hasRefreshToken -or $PSBoundParameters.ContainsKey('ClientId') -or $PSBoundParameters.ContainsKey('ClientSecret')) {
        throw "OAuth credentials/secrets are not used with -AuthMode SessionDerived; omit them to avoid accidental mixing of auth modes."
    }
}
else {
    if ($hasPassword -and $hasRefreshToken) { throw 'Specify either -Password or -RefreshToken, not both, when using OAuth.' }
    if (-not $hasPassword -and -not $hasRefreshToken) { throw 'Specify one authentication method (-Password or -RefreshToken) when using OAuth.' }
}

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

function ConvertTo-HttpSafeUserAgent {
    <#
    .SYNOPSIS
    Converts a Reddit-style User-Agent (often contains ':') into an HTTP/.NET-safe User-Agent.

    .DESCRIPTION
    PowerShell's Invoke-WebRequest/Invoke-RestMethod (HttpClient) validates User-Agent as RFC-compliant
    product tokens (e.g. name/version). Reddit commonly recommends "platform:app:version (by /u/name)",
    but colons are not valid in product tokens and can throw.
    #>
    param(
        [AllowNull()]
        [string]$UserAgent
    )

    if ([string]::IsNullOrWhiteSpace([string]$UserAgent)) { return $UserAgent }
    $ua = ([string]$UserAgent).Trim()

    # Preferred input format: platform:app:version (by /u/name)
    $m = [regex]::Match($ua, '^(?<platform>[^:\s]+):(?<app>[^:\s]+):(?<version>[^\s]+)\s*(?<rest>.*)$')
    if ($m.Success) {
        $platform = $m.Groups['platform'].Value
        $app = $m.Groups['app'].Value
        $version = $m.Groups['version'].Value
        $rest = ($m.Groups['rest'].Value ?? '').Trim()

        # Keep the informational "by /u/..." if present, but place it inside an RFC comment.
        # Example: windows:MyApp:v1.0 (by /u/me) -> MyApp/v1.0 (windows; by /u/me)
        if ($rest.StartsWith('(') -and $rest.EndsWith(')')) {
            $rest = $rest.TrimStart('(').TrimEnd(')').Trim()
        }
        if ([string]::IsNullOrWhiteSpace($rest)) {
            return "$app/$version ($platform)"
        }
        return "$app/$version ($platform; $rest)"
    }

    # If the caller already supplied a conventional UA (contains name/version), keep it.
    if ($ua -match '\S+/\S+') { return $ua }

    # Last-resort: wrap the original as a comment after a known-safe product token.
    return "RedditCommentKiller/1.0 ($ua)"
}

# Auto-generate UserAgent if not provided (Reddit API requirement)
if ([string]::IsNullOrWhiteSpace($UserAgent)) {
    $platform = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } elseif ($IsLinux) { 'linux' } else { 'unknown' }
    $uaUser = [string]::IsNullOrWhiteSpace($Username) ? 'anonymous' : $Username
    # Use an RFC/HttpClient-safe UA by default.
    $UserAgent = "RedditCommentKiller/1.0 ($platform; by /u/$uaUser)"
    if ($VerboseLogging) { Write-Verbose "Generated UserAgent: $UserAgent" }
}

# Normalize *any* provided UserAgent to a safe, RFC-compliant format for HttpClient/Invoke-WebRequest.
$UserAgent = ConvertTo-HttpSafeUserAgent -UserAgent $UserAgent

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

function ConvertTo-NormalizedSubredditName {
    <#
    .SYNOPSIS
    Normalizes subreddit names to a canonical form for comparisons.
    #>
    param(
        [AllowNull()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace([string]$Name)) { return $null }
    $s = ([string]$Name).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }

    $s = $s.Trim('/')
    if ($s.StartsWith('r/', [System.StringComparison]::OrdinalIgnoreCase)) {
        $s = $s.Substring(2)
    }
    $s = $s.Trim().Trim('/')
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    return $s
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

# Script-level variable to store verified authenticated username (from /api/v1/me)
$Script:AuthenticatedUsername = $null

# Script-level variable to store session-derived token details (kept in-memory only)
$Script:SessionTokenInfo = $null

# Script-level variable to hold the active auth provider instance
$Script:AuthProvider = $null

# Minimum spacing between Reddit API calls (fallback for endpoints that omit rate-limit headers).
# Reddit's published free-access guidance is ~100 queries/minute (~0.6s per request).
$Script:RedditApiMinRequestIntervalSeconds = 0.6
$Script:RedditApiLastRequestAtUtc = $null

function Test-IsHtmlContent {
    <#
    .SYNOPSIS
    Detects whether a response body appears to be HTML (challenge/defense page).
    #>
    param(
        [AllowNull()]
        [string]$Content
    )

    if ([string]::IsNullOrWhiteSpace([string]$Content)) { return $false }
    $trimmed = ([string]$Content).Trim()
    return ($trimmed -match '<!DOCTYPE html|<html')
}

function Build-RedditUri {
    <#
    .SYNOPSIS
    Combines the provider's base URI with a relative path.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Initialize-AuthProvider

    $base = $null
    if ($Script:AuthProvider -and $Script:AuthProvider.PSObject.Properties.Match('ApiBaseUri').Count -gt 0) {
        $base = [string]$Script:AuthProvider.ApiBaseUri
    }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = 'https://oauth.reddit.com' }

    $normalizedPath = $Path
    if (-not $normalizedPath.StartsWith('/')) { $normalizedPath = "/$normalizedPath" }
    return ($base.TrimEnd('/') + $normalizedPath)
}

function New-OAuthProvider {
    <#
    .SYNOPSIS
    Creates an OAuth-backed auth provider that reuses the existing token flow.
    #>
    $provider = [PSCustomObject]@{
        Name            = 'OAuth'
        ApiBaseUri      = 'https://oauth.reddit.com'
        SupportsRefresh = $true
    }

    $provider | Add-Member -MemberType ScriptMethod -Name EnsureValidAuth -Value {
        Confirm-AccessToken
        if (-not $Script:TokenInfo -or [string]::IsNullOrWhiteSpace([string]$Script:TokenInfo.AccessToken)) {
            throw 'Access token missing after Confirm-AccessToken.'
        }
    } -Force

    $provider | Add-Member -MemberType ScriptMethod -Name GetAuthHeaders -Value {
        if (-not $Script:TokenInfo -or [string]::IsNullOrWhiteSpace([string]$Script:TokenInfo.AccessToken)) {
            throw 'Access token missing when building headers.'
        }
        return @{ 'Authorization' = "bearer $($Script:TokenInfo.AccessToken)"; 'User-Agent' = $UserAgent }
    } -Force

    $provider | Add-Member -MemberType ScriptMethod -Name TryRefreshOnce -Value {
        Get-AccessToken -ClientId $ClientId -ClientSecret $ClientSecret -Username $Username -Password $Password -RefreshToken $RefreshToken -UserAgent $UserAgent
        return $true
    } -Force

    return $provider
}

function New-SessionDerivedTokenProvider {
    <#
    .SYNOPSIS
    Creates a session-derived-token provider (token stays in-memory only).
    #>
    $token = $null
    if ($SessionAccessToken) {
        $token = ConvertFrom-SecureStringPlain -Secure $SessionAccessToken
    }
    if ([string]::IsNullOrWhiteSpace([string]$token)) {
        throw 'SessionDerived auth requires a non-empty session-derived token.'
    }

    $Script:SessionTokenInfo = [PSCustomObject]@{
        Token  = $token
        Scheme = $SessionAuthorizationScheme
        Source = $SessionSecretName
        ApiBaseUri = $SessionApiBaseUri
    }

    $provider = [PSCustomObject]@{
        Name            = 'SessionDerived'
        ApiBaseUri      = $SessionApiBaseUri
        SupportsRefresh = $false
    }

    $provider | Add-Member -MemberType ScriptMethod -Name EnsureValidAuth -Value {
        if (-not $Script:SessionTokenInfo -or [string]::IsNullOrWhiteSpace([string]$Script:SessionTokenInfo.Token)) {
            throw 'Session-derived token missing.'
        }
    } -Force

    $provider | Add-Member -MemberType ScriptMethod -Name GetAuthHeaders -Value {
        if (-not $Script:SessionTokenInfo -or [string]::IsNullOrWhiteSpace([string]$Script:SessionTokenInfo.Token)) {
            throw 'Session-derived token missing when building headers.'
        }
        $scheme = [string]$Script:SessionTokenInfo.Scheme
        if ([string]::IsNullOrWhiteSpace($scheme)) { $scheme = 'bearer' }
        return @{ 'Authorization' = "$scheme $($Script:SessionTokenInfo.Token)"; 'User-Agent' = $UserAgent }
    } -Force

    $provider | Add-Member -MemberType ScriptMethod -Name TryRefreshOnce -Value {
        # Session-derived tokens are assumed non-refreshable; caller should stop on auth failures.
        return $false
    } -Force

    return $provider
}

function New-AuthProvider {
    <#
    .SYNOPSIS
    Factory for the configured auth mode.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    switch -Regex ($Mode) {
        '^OAuth$'          { return New-OAuthProvider }
        '^SessionDerived$' { return New-SessionDerivedTokenProvider }
        default { throw "Unsupported AuthMode '$Mode'." }
    }
}

function Initialize-AuthProvider {
    <#
    .SYNOPSIS
    Ensures the script-level auth provider exists.
    #>
    if ($null -eq $Script:AuthProvider) {
        $Script:AuthProvider = New-AuthProvider -Mode $AuthMode
    }
}

function Confirm-AuthIsReady {
    <#
    .SYNOPSIS
    Ensures the provider has valid auth state before a request.
    #>
    Initialize-AuthProvider
    $Script:AuthProvider.EnsureValidAuth.Invoke()
}

function Get-AuthHeadersFromProvider {
    <#
    .SYNOPSIS
    Retrieves headers from the active auth provider.
    #>
    Initialize-AuthProvider
    return $Script:AuthProvider.GetAuthHeaders.Invoke()
}

function Invoke-AuthRefreshOnce {
    <#
    .SYNOPSIS
    Attempts a single refresh via the provider (if supported).
    #>
    Initialize-AuthProvider
    if ($Script:AuthProvider.PSObject.Methods.Match('TryRefreshOnce').Count -gt 0) {
        return [bool]$Script:AuthProvider.TryRefreshOnce.Invoke()
    }
    return $false
}

function Get-AccessToken {
    <#
    .SYNOPSIS
    Obtains OAuth access token using Reddit's password grant or refresh-token grant.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [SecureString]$Password,
        [SecureString]$RefreshToken,
        [string]$UserAgent
    )

    # Convert SecureString secret(s) to plain text only for this API call.
    # Prefer refresh-token grant when available to avoid handling account passwords.
    $plainPassword = $null
    $plainRefreshToken = $null

    # Reddit requires Basic authentication with client_id:client_secret
    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ClientId}:$ClientSecret"))

    $headers = @{ 'User-Agent' = $UserAgent; Authorization = "Basic $basicAuth" }

    try {
        $usingRefresh = $null -ne $RefreshToken
        $usingPassword = $null -ne $Password

        if ($usingRefresh -and $usingPassword) {
            throw 'Get-AccessToken requires exactly one of -Password or -RefreshToken.'
        }
        if (-not $usingRefresh -and -not $usingPassword) {
            throw 'Get-AccessToken requires one authentication method: -Password or -RefreshToken.'
        }

        if ($usingRefresh) {
            $plainRefreshToken = ConvertFrom-SecureStringPlain -Secure $RefreshToken
            if ([string]::IsNullOrWhiteSpace($plainRefreshToken)) {
                throw 'RefreshToken was empty.'
            }
            $body = @{ grant_type = 'refresh_token'; refresh_token = $plainRefreshToken }
        }
        else {
            $plainPassword = ConvertFrom-SecureStringPlain -Secure $Password
            if ([string]::IsNullOrWhiteSpace($plainPassword)) {
                throw 'Password was empty.'
            }
            $body = @{ grant_type = 'password'; username = $Username; password = $plainPassword }
        }

        # Request access token from Reddit's OAuth endpoint
        $resp = Invoke-RestMethod -Method Post -Uri 'https://www.reddit.com/api/v1/access_token' -Headers $headers -Body $body -ErrorAction Stop
    }
    finally {
        # Best-effort: shorten lifetime of managed strings (cannot truly zero a .NET string).
        $plainPassword = $null
        $plainRefreshToken = $null
    }

    # Calculate expiration time with 30-second buffer to ensure we refresh before actual expiry.
    # Be defensive: expires_in can be missing or non-numeric; default to 3600s in that case.
    $expiresInSeconds = 3600
    try {
        $tmp = 0
        if ($null -ne $resp -and $resp.PSObject.Properties.Match('expires_in').Count -gt 0 -and [int]::TryParse([string]$resp.expires_in, [ref]$tmp) -and $tmp -gt 0) {
            $expiresInSeconds = $tmp
        }
        elseif ($VerboseLogging) {
            Write-Verbose "Token response missing/invalid expires_in; defaulting expiry to ${expiresInSeconds}s"
        }
    }
    catch {
        if ($VerboseLogging) { Write-Verbose "Token response expires_in parsing failed; defaulting expiry to ${expiresInSeconds}s" }
    }

    $bufferSeconds = 30
    $effectiveExpiresIn = [Math]::Max($expiresInSeconds - $bufferSeconds, 1)
    $expiresAt = (Get-Date).ToUniversalTime().AddSeconds($effectiveExpiresIn)

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
        Get-AccessToken -ClientId $ClientId -ClientSecret $ClientSecret -Username $Username -Password $Password -RefreshToken $RefreshToken -UserAgent $UserAgent
    }
}

function Confirm-AuthenticatedIdentity {
    <#
    .SYNOPSIS
    Verifies the authenticated user via /api/v1/me and caches the username.
    #>

    if (-not [string]::IsNullOrWhiteSpace($Script:AuthenticatedUsername)) { return }

    Confirm-AuthIsReady
    $headers = Get-AuthHeadersFromProvider
    $meUri = Build-RedditUri -Path '/api/v1/me'

    $refreshed = $false
    try {
        $resp = Invoke-WebRequest -Method Get -Uri $meUri -Headers $headers -ErrorAction Stop
    }
    catch {
        $status = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        }
        catch { $status = $null }

        if (($status -eq 401 -or $status -eq 403) -and -not $refreshed) {
            $refreshed = Invoke-AuthRefreshOnce
            if ($refreshed) {
                Confirm-AuthIsReady
                $headers = Get-AuthHeadersFromProvider
                $resp = Invoke-WebRequest -Method Get -Uri $meUri -Headers $headers -ErrorAction Stop
            }
            else {
                throw "Authentication failed for /api/v1/me (status $status). Provider could not refresh; stop to avoid acting unauthenticated."
            }
        }
        else {
            throw
        }
    }

    $rawContent = $resp.Content
    if ([string]::IsNullOrWhiteSpace([string]$rawContent)) {
        throw 'Unable to verify authenticated user via /api/v1/me (empty response body).'
    }
    if (Test-IsHtmlContent -Content $rawContent) {
        throw 'Unexpected HTML response from Reddit /api/v1/me (possible auth/rate-limit/protection page).'
    }

    $me = $null
    try {
        $me = $rawContent | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $snippetLength = [Math]::Min([int]$rawContent.Length, 500)
        $snippet = $rawContent.Substring(0, $snippetLength)
        $snippet = $snippet -replace "`r", '' -replace "`n", ' '
        $parseMsg = $_.Exception.Message
        throw "Unable to verify authenticated user via /api/v1/me (JSON parse failed). $parseMsg Snippet: $snippet"
    }

    $name = $null
    if ($null -ne $me -and $me.PSObject.Properties.Match('name').Count -gt 0) {
        $name = [string]$me.name
    }

    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "Unable to verify authenticated user via /api/v1/me (missing name in response)."
    }

    $Script:AuthenticatedUsername = $name
    if ($VerboseLogging) { Write-Verbose "Authenticated as /u/$($Script:AuthenticatedUsername) (verified via /api/v1/me)" }

    # If a username was provided, enforce it matches; otherwise adopt the authenticated username for targeting/reporting.
    if (-not [string]::IsNullOrWhiteSpace($Username)) {
        if (-not [string]::Equals($Script:AuthenticatedUsername, $Username, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Authenticated as /u/$($Script:AuthenticatedUsername), but -Username was '$Username'. Refusing to continue to avoid targeting the wrong account or doing a silent no-op."
        }
    }
    else {
        $script:Username = $Script:AuthenticatedUsername
    }
}

function Assert-RedditApiOk {
    <#
    .SYNOPSIS
    Throws if Reddit API returned structured errors.
    #>
    param(
        $Data,
        [string]$Context
    )

    if ($null -eq $Data) { return }

    if ($Data.PSObject.Properties.Match('json').Count -gt 0 -and $Data.json) {
        if ($Data.json.PSObject.Properties.Match('errors').Count -gt 0 -and $Data.json.errors -and $Data.json.errors.Count -gt 0) {
            $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
            $errorsJson = $Data.json.errors | ConvertTo-Json -Compress
            throw "Reddit API returned errors${ctx}: $errorsJson"
        }
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

function Invoke-RedditRequest {
    <#
    .SYNOPSIS
    Wrapper for Reddit API calls with automatic retry, rate-limit handling, and provider-driven auth.
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

    Confirm-AuthIsReady

    # Retry configuration for transient failures
    $maxAttempts = 5
    $attempt = 0
    $backoff = 2  # Initial backoff in seconds, doubles on each retry
    $refreshedOnAuthFailure = $false

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

        # Build provider-supplied auth headers
        $headers = Get-AuthHeadersFromProvider

        # Prepare request parameters.
        # Some PowerShell builds do not support -ResponseHeadersVariable; fall back to resp.Headers.
        $params = @{ Method = $Method; Uri = $Uri; Headers = $headers; ErrorAction = 'Stop' }
        $supportsResponseHeadersVariable = $false
        try {
            $supportsResponseHeadersVariable = (Get-Command Invoke-WebRequest -ErrorAction Stop).Parameters.ContainsKey('ResponseHeadersVariable')
        }
        catch {
            $supportsResponseHeadersVariable = $false
        }

        if ($supportsResponseHeadersVariable) {
            $params.ResponseHeadersVariable = 'respHeaders'
        }
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = 'application/x-www-form-urlencoded'
        }

        # Build query string with proper URL encoding if query parameters provided
        if ($Query) {
            $pairs = foreach ($entry in $Query.GetEnumerator()) {
                $k = [string]$entry.Key
                if ([string]::IsNullOrWhiteSpace($k)) { continue }

                $v = $entry.Value
                if ($null -eq $v) { continue }

                $kEsc = [uri]::EscapeDataString($k)
                $vEsc = [uri]::EscapeDataString([string]$v)
                "{0}={1}" -f $kEsc, $vEsc
            }

            $qs = ($pairs -join '&')

            if ($qs) {
                $params.Uri = "$($Uri)?$qs"
            }
            else {
                $params.Uri = $Uri
            }
        }

        # Fail early with a clear message if we built a malformed URI.
        try {
            [void][System.Uri]::new([string]$params.Uri)
        }
        catch {
            $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
            throw "Built invalid URI$ctx for ${Method}: '$($params.Uri)'. $($_.Exception.Message)"
        }

        try {
            # Track request start time to maintain minimum spacing even when requests fail/retry.
            $Script:RedditApiLastRequestAtUtc = [DateTimeOffset]::UtcNow

            # Execute the HTTP request
            $resp = Invoke-WebRequest @params

            # Normalize headers to a simple hashtable with lower-cased keys.
            if (-not $supportsResponseHeadersVariable) {
                $respHeaders = @{}
                try {
                    if ($resp -and $resp.PSObject.Properties.Match('Headers').Count -gt 0 -and $resp.Headers) {
                        $h = $resp.Headers

                        # Common case: IDictionary
                        if ($h -is [System.Collections.IDictionary]) {
                            foreach ($k in $h.Keys) {
                                if ($null -eq $k) { continue }
                                $key = ([string]$k).ToLowerInvariant()
                                $respHeaders[$key] = $h[$k]
                            }
                        }
                        else {
                            # Best-effort enumerator support
                            $enum = $null
                            try { $enum = $h.GetEnumerator() } catch { $enum = $null }
                            if ($enum) {
                                foreach ($entry in $enum) {
                                    if ($null -eq $entry) { continue }
                                    $key = ([string]$entry.Key).ToLowerInvariant()
                                    $respHeaders[$key] = $entry.Value
                                }
                            }
                        }
                    }
                }
                catch {
                    # If we cannot read headers, leave empty and proceed (rate-limit logic becomes conservative).
                    $respHeaders = @{}
                }
            }

            $content = $null
            $rawContent = $resp.Content
            $parseError = $null

            if ($rawContent) {
                $trimmed = ([string]$rawContent).Trim()

                # AllowNonJsonResponse is intended for endpoints that return empty/opaque bodies, not HTML defenses.
                if (Test-IsHtmlContent -Content $trimmed) {
                    throw "Unexpected HTML response from Reddit (possible auth/rate-limit/protection page)."
                }

                # If it looks like JSON, parse it strictly even when AllowNonJsonResponse is set.
                $looksJson = $trimmed.StartsWith('{') -or $trimmed.StartsWith('[')
                if (-not $AllowNonJsonResponse -or $looksJson) {
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
                    # Non-JSON body allowed only when explicitly requested.
                    $content = $null
                }
            }

            # For write endpoints that allow non-JSON bodies, ensure we still got a success status.
            $statusCode = $null
            try {
                if ($resp.PSObject.Properties.Match('StatusCode').Count -gt 0 -and $null -ne $resp.StatusCode) {
                    $statusCode = [int]$resp.StatusCode
                }
                elseif ($resp.StatusCode -and $null -ne $resp.StatusCode.value__) {
                    $statusCode = [int]$resp.StatusCode.value__
                }
            }
            catch {
                $statusCode = $null
            }

            if ($IsWrite -and $AllowNonJsonResponse -and $null -ne $statusCode -and $statusCode -ne 200 -and $statusCode -ne 204) {
                $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
                throw "Unexpected status code $statusCode for $Method $Uri$ctx (expected 200/204)."
            }

            if ($IsWrite) {
                Assert-RedditApiOk -Data $content -Context $Context
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

                    if ($resp -is [System.Net.Http.HttpResponseMessage]) {
                        $values = $null
                        if ($resp.Headers.TryGetValues('Retry-After', [ref]$values)) {
                            $raRaw = @($values) | Select-Object -First 1
                        }
                        elseif ($resp.Headers.RetryAfter) {
                            if ($resp.Headers.RetryAfter.Delta) {
                                $retryAfterSeconds = [int][math]::Ceiling($resp.Headers.RetryAfter.Delta.TotalSeconds)
                            }
                            elseif ($resp.Headers.RetryAfter.Date) {
                                $until = $resp.Headers.RetryAfter.Date.UtcDateTime - (Get-Date).ToUniversalTime()
                                $retryAfterSeconds = [int][math]::Ceiling($until.TotalSeconds)
                            }
                        }
                    }
                    elseif ($resp.PSObject.Properties.Match('Headers').Count -gt 0 -and $resp.Headers) {
                        # Other response shapes; fall back to Headers property access
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

            # 401/403: allow one refresh attempt, then stop
            if (($status -eq 401 -or $status -eq 403) -and -not $refreshedOnAuthFailure -and $attempt -lt $maxAttempts) {
                $ctx = ([string]::IsNullOrWhiteSpace($Context)) ? '' : " [$Context]"
                Write-Warning "API call returned $status$ctx; attempting a single auth refresh."
                $refreshed = Invoke-AuthRefreshOnce
                if ($refreshed) {
                    $refreshedOnAuthFailure = $true
                    Confirm-AuthIsReady
                    continue
                }

                throw "Authentication failed with status $status$ctx and refresh is unsupported/failed. Stopping to avoid unauthenticated actions."
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

    $targetUser = $Script:AuthenticatedUsername
    if ([string]::IsNullOrWhiteSpace($targetUser)) { $targetUser = $Username }
    $uri = Build-RedditUri -Path "/user/$targetUser/comments"
    Invoke-RedditRequest -Method Get -Uri $uri -Query $query
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
        [System.Collections.Generic.HashSet[string]]$Set
    )

    if ($null -eq $Set) {
        $Set = [System.Collections.Generic.HashSet[string]]::new()
    }

    if ([string]::IsNullOrWhiteSpace([string]$ProcessedLogPath)) {
        Write-Output -NoEnumerate $Set
        return
    }

    try {
        if (-not (Test-Path -Path $ProcessedLogPath)) {
            Write-Output -NoEnumerate $Set
            return
        }
    }
    catch {
        Write-Output -NoEnumerate $Set
        return
    }

    foreach ($line in (Get-Content -Path $ProcessedLogPath -ErrorAction SilentlyContinue)) {
        $id = [string]$line
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $Set.Add($id.Trim()) | Out-Null
    }

    Write-Output -NoEnumerate $Set
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
            if ($VerboseLogging) {
                $ex = $_.Exception
                $typeName = ($null -ne $ex) ? $ex.GetType().FullName : 'unknown'
                $msg = ($null -ne $ex) ? $ex.Message : 'unknown error'
                $innerMsg = ($null -ne $ex -and $ex.InnerException) ? $ex.InnerException.Message : $null
                $extra = [string]::IsNullOrWhiteSpace($innerMsg) ? '' : " Inner: $innerMsg"
                Write-Verbose "Failed to parse checkpoint at '$ResumePath': ${typeName}: $msg$extra"
            }
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

function ConvertTo-SafeCsvCell {
    <#
    .SYNOPSIS
    Prevents CSV formula injection when opening reports in spreadsheet apps.
    #>
    param(
        [AllowNull()]
        [string]$Value
    )
    if ($null -eq $Value) { return '' }
    if ($Value -match '^[=\+\-@]') { return "'$Value" }
    return $Value
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

$processedSet = Import-ProcessedLog
if ($null -eq $processedSet) {
    $processedSet = [System.Collections.Generic.HashSet[string]]::new()
}

$excludedSubredditsSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($PSBoundParameters.ContainsKey('ExcludedSubredditsFile') -and -not [string]::IsNullOrWhiteSpace($ExcludedSubredditsFile)) {
    foreach ($line in (Get-Content -Path $ExcludedSubredditsFile -ErrorAction Stop)) {
        $raw = [string]$line
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $trimmed = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith('#')) { continue }

        $normalized = ConvertTo-NormalizedSubredditName -Name $trimmed
        if ($normalized) {
            $excludedSubredditsSet.Add($normalized) | Out-Null
        }
    }

    Write-Host "Loaded $($excludedSubredditsSet.Count) excluded subreddits from $ExcludedSubredditsFile" -ForegroundColor Cyan
}

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

# Initialize auth provider early to surface auth-mode issues before destructive actions
Initialize-AuthProvider

# Verify authenticated identity once and use it for listing/reporting
Confirm-AuthenticatedIdentity
Write-Host "Authenticated as /u/$($Script:AuthenticatedUsername)" -ForegroundColor Green

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
        # Guard against malformed/empty created_utc values (can otherwise flip $pastCutoffZone too early).
        $createdUtcSeconds = 0L
        $createdUtc = $null
        try {
            $rawCreated = $comment.created_utc
            if ($null -ne $rawCreated) {
                if ($rawCreated -is [double] -or $rawCreated -is [float] -or $rawCreated -is [decimal]) {
                    $createdUtcSeconds = [int64][math]::Floor([double]$rawCreated)
                }
                else {
                    $createdUtcSeconds = [int64]$rawCreated
                }
            }
        }
        catch {
            $createdUtcSeconds = 0L
        }
        if ($createdUtcSeconds -gt 0) {
            $createdUtc = [DateTimeOffset]::FromUnixTimeSeconds($createdUtcSeconds).UtcDateTime
        }
        else {
            if ($VerboseLogging) { Write-Verbose "Skipping item with missing/invalid created_utc (fullname=$($comment.name))" }
            continue
        }

        # Extract comment identifiers and metadata
        $fullname = $comment.name  # Reddit's full thing ID (e.g., "t1_abc123")
        if ([string]::IsNullOrWhiteSpace($fullname)) { continue }

        $permalink = "https://www.reddit.com$($comment.permalink)"
        $subreddit = $comment.subreddit
        if ([string]::IsNullOrWhiteSpace([string]$subreddit) -and $comment.PSObject.Properties.Match('subreddit_name_prefixed').Count -gt 0) {
            $subreddit = $comment.subreddit_name_prefixed
        }
        $subredditNormalized = ConvertTo-NormalizedSubredditName -Name ([string]$subreddit)

        # Safety rule: never process anything newer than the cutoff, even if Reddit returns out-of-order items.
        if ($createdUtc -gt $effectiveCutoffUtc) { continue }

        # Listing is typically newest -> oldest. Once we see the first older-than-cutoff item, we are in the cutoff zone.
        if (-not $pastCutoffZone) { $pastCutoffZone = $true }

        # Optional exclusion: skip comments in excluded subreddits before accounting for paging stop logic.
        if ($excludedSubredditsSet.Count -gt 0 -and $subredditNormalized -and $excludedSubredditsSet.Contains($subredditNormalized)) {
            if ($VerboseLogging) { Write-Verbose "Skipping $fullname in excluded subreddit r/$subredditNormalized" }
            continue
        }

        # Once past the cutoff, track per-page older-item stats for stop-optimizations
        if ($pastCutoffZone) { $pageOlderTotal++ }

        # Skip if already processed in previous run (resume functionality)
        if ($processedSet.Contains($fullname)) { continue }

        if ($pastCutoffZone) { $pageOlderUnprocessed++ }

        $summary.matched++
        $actionDesc = "comment $fullname"

        # Honor -WhatIf parameter (CmdletBinding SupportsShouldProcess)
        if (-not $PSCmdlet.ShouldProcess($actionDesc, 'Process')) { continue }

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
                    $null = Invoke-RedditRequest -Method Post -Uri (Build-RedditUri -Path '/api/editusertext') -Body $body -IsWrite -Context $fullname
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
                        $null = Invoke-RedditRequest -Method Post -Uri (Build-RedditUri -Path '/api/editusertext') -Body $body2 -IsWrite -Context $fullname
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
                $body = @{ api_type = 'json'; id = $fullname }
                $null = Invoke-RedditRequest -Method Post -Uri (Build-RedditUri -Path '/api/del') -Body $body -IsWrite -Context $fullname
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
            permalink   = ConvertTo-SafeCsvCell -Value $permalink
            subreddit   = ConvertTo-SafeCsvCell -Value ([string]$subreddit)
            fullname    = ConvertTo-SafeCsvCell -Value $fullname
                action      = $OverwriteEnabled ? ($doTwoPass ? '2xedit+delete' : 'edit+delete') : 'delete'
            status      = ConvertTo-SafeCsvCell -Value "$editStatus/$deleteStatus"
            error       = ConvertTo-SafeCsvCell -Value $errorMessage
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
