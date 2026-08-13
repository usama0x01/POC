#requires -Version 5.1
<#
================================================================================
 Hunt-ClickFix-Compromise.ps1   -   Tabby "ClickFix / Citrix" incident sweep
================================================================================
 AD-wide (or list/local) evidence-of-compromise sweep for the HelpJuice->ClickFix
 PowerShell loader (rescrewify / vacuumtubr campaign). Read-only. Windows PS 5.1.

 Delivery vector (confirmed): compromised HelpJuice KB -> fake CAPTCHA -> user pastes
 PowerShell into VDI/endpoint -> stage payload -> scheduled-task beacon that exfils
 hostname/username/SID and awaits stage 3.

 WHAT IT CHECKS per host:
   Host    - drop dir C:\ProgramData\Balleticalless + unholdible.ps1/.txt + profile
             cache file (+ SHA256 + dir listing)
           - scheduled task \Unlearningest\Lengthwisization\Undraftment
             (task object + task XML file + TaskCache registry)
           - generic heuristic: hidden PowerShell task launched from ProgramData
           - live beacon process (powershell referencing Balleticalless/unholdible)
   Network - DNS client cache + hosts file + active TCP connections vs 168 campaign
             domains and 3 C2 IPs
   Logs    - (opt-in) TaskScheduler, PowerShell 4104 (campaign-unique tokens, with
             self-exclusion), Sysmon 1/11/22, Security 4688

 CHANNELS (per host, best available):
   1. WinRM  (Invoke-Command)      -> FULL   coverage
   2. SMB C$ (New-PSDrive)         -> PARTIAL (files + task file + hosts file only)
   otherwise                        -> UNREACHABLE

 VERDICTS: INFECTED / SUSPICIOUS / REVIEW / CLEAN(full) / CLEAN_PARTIAL(smb-only) /
           UNREACHABLE   (CLEAN_PARTIAL means "no host-file IOCs, but registry/process/
           DNS/logs were NOT checked - not a full clearance")

 USAGE:
   .\Hunt-ClickFix-Compromise.ps1 -Local -IncludeEventLogs
   .\Hunt-ClickFix-Compromise.ps1 -FromAD -IncludeEventLogs -OutputDirectory C:\IR
   .\Hunt-ClickFix-Compromise.ps1 -ComputerName VDI01,VDI02 -Credential (Get-Credential)
   .\Hunt-ClickFix-Compromise.ps1 -ComputerListFile .\hosts.txt -NoSmbFallback

 Run as a Domain Admin from a management host / DC. Read-only (no -Remediate here).
================================================================================
#>
[CmdletBinding(DefaultParameterSetName = 'AD')]
param(
    [Parameter(ParameterSetName = 'List')]  [string[]] $ComputerName,
    [Parameter(ParameterSetName = 'File')]  [string]   $ComputerListFile,
    [Parameter(ParameterSetName = 'AD')]    [switch]   $FromAD,
    [Parameter(ParameterSetName = 'AD')]    [string]   $SearchBase,
    [Parameter(ParameterSetName = 'Local')] [switch]   $Local,
    [switch]                                           $IncludeEventLogs,
    [switch]                                           $NoSmbFallback,
    [System.Management.Automation.PSCredential] $Credential,
    [int]      $ThrottleLimit  = 32,
    [int]      $SmbThrottle    = 15,
    [int]      $TcpTimeoutMs   = 700,
    [string]   $OutputDirectory = 'C:\IR\ClickFixSweep',
    [string[]] $ExpectedTestHosts = @()
)

$ScriptVersion = '2.0  (2026-08-13  consolidated)'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

# ------------------------------------------------------------------------------
# Pretty output (glyphs built from [char] codes -> source stays pure ASCII)
# ------------------------------------------------------------------------------
$VColor = @{ INFECTED='Red'; SUSPICIOUS='Yellow'; REVIEW='DarkYellow'; CLEAN='Green'
            CLEAN_PARTIAL='DarkGreen'; UNREACHABLE='DarkGray'; EXPECTED_HIT='Magenta' }
$VTag   = @{ INFECTED='[INFECTED]'; SUSPICIOUS='[SUSPECT ]'; REVIEW='[REVIEW  ]'; CLEAN='[CLEAN   ]'
            CLEAN_PARTIAL='[CLEAN~  ]'; UNREACHABLE='[NO-CONN ]'; EXPECTED_HIT='[TEST-HIT]' }
$SColor = @{ CRITICAL='Red'; HIGH='Red'; MEDIUM='Yellow'; LOW='DarkCyan' }
$Glyph  = @{ Full=[string][char]0x2588; Light=[string][char]0x2591
             Arrow=[string][char]0x2514 + [string][char]0x2500 + '> ' }
function Write-Rule { param([string]$Ch=[string][char]0x2550,[int]$W=74,[string]$Color='DarkCyan')
    Write-Host ($Ch * $W) -ForegroundColor $Color }
function Get-Bar { param([int]$V,[int]$T,[int]$W=24)
    if ($T -le 0){$T=1}; $f=[int][math]::Round(($V/$T)*$W); if($f -gt $W){$f=$W}; if($f -lt 0){$f=0}
    ($Glyph.Full*$f)+($Glyph.Light*($W-$f)) }

# ------------------------------------------------------------------------------
# IOC set (single source of truth; passed into remote/SMB workers)
# ------------------------------------------------------------------------------
$IOC = @{
    DropDir        = 'C:\ProgramData\Balleticalless'
    DropFiles      = @('unholdible.ps1','unholdible.txt','bSSGkZQnXwANzQkfDhlqpNOVfwfTKP')
    TaskName       = 'Undraftment'
    TaskPath       = '\Unlearningest\Lengthwisization\'
    TaskFolder1    = 'Unlearningest'
    TaskFolder2    = 'Lengthwisization'
    ContentMarkers = @('nKTOgWshe7dqBMO','bSSGkZQnXwANzQkfDhlqpNOVfwfTKP')
    C2IPs          = @('178.16.55.232','88.80.150.25','147.45.221.17')
    # unique 4104 tokens (NOT generic AMSI/ETW strings -> avoids FPs & self-detection)
    LogTokens      = @('rescrewify','vacuumtubr','refictionify','keelhaulably','qsEbYMrEGBjttn',
                       'Balleticalless','unholdible','nKTOgWshe7dqBMO','bSSGkZQnXwANzQkfDhlqpNOVfwfTKP')
    Sentinel       = 'HUNTSELF_7Q2X9'   # excludes THIS hunt's own script-block events
    Domains        = @(
    'abandoningality.net','abledom.net','acquisitional.net','avprog.cc','avservice.cc','avsprog.cc',
    'avumanager.network','backgroundtions.com','bacteremiaation.com','brightnessably.net',
    'calibrationists.com','californiums.net','dangerouslified.com','deliberatst.net','descendantably.com',
    'divingment.com','earthquaking.net','eavesdroppingest.com','encryptionism.net','fabricationers.com',
    'finchish.com','frighteningality.net','gardeniasally.com','greenhouseable.net','habitationally.com',
    'householdsable.net','icebreakerable.net','incredibleally.net','jackhammerable.net','jailbreakss.com',
    'jquerycdnhost.com','justifiablyized.com','kaleidoscopeally.net','karyogramed.com','karyotypestion.net',
    'keelhaulably.com','laboratoryism.com','likelihoodtion.com','lmsevice.cc','machinistsation.net',
    'medicationism.net','misaffordic.com','misbendish.net','miscourtize.net','misemployible.com',
    'misgaugeic.com','misjuggleish.com','mislabeledless.com','mislittle.com','mismightyify.com',
    'misrapidise.com','missizeic.com','missoaklike.com','mistoelike.com','misunliking.net','misvividful.com',
    'miswinkish.com','msconfig.cc','nakedible.com','narrativesably.com','nationhoodization.com',
    'nationwidely.net','nonacquireish.com','nonangrying.com','nonembassyful.com','nonforgiveise.net',
    'nonindoorible.com','nonkneelship.com','nononlinelike.com','nonpoisonship.com','nonporterible.net',
    'nonsailingise.com','nonscaleal.com','nucleotidally.com','overdeliverment.com','overencrypts.com',
    'overexplodement.com','overlateise.com','overmigrateise.net','overpermited.com','overshelfic.com',
    'overstackment.com','overtomatoable.com','overupgradedom.com','pacemakerists.com','pathogenicists.com',
    'peanuthood.com','plugins-manager.network','preadoptless.com','preauditify.net','preaxeise.com',
    'prebadize.com','precheetah.net','precostment.com','preenactable.com','premotivateless.com',
    'prenewtic.com','preonlyable.net','prestimulateless.com','prewondered.com','preworkless.com',
    'profkatz.com','quadrangling.net','queryize.com','quotationsing.com','radiationsism.com','rebronzeal.com',
    'recontestish.net','redetailedify.com','refictionify.com','refootful.com','refreshingest.net',
    'regivehood.com','rehearify.com','reknitless.com','repossibleish.com','rerequiredful.com',
    'rescrewify.net','resimpleship.net','retimelyize.net','rewarnise.com','safeguardses.com',
    'sailboaterists.net','strapness.com','tablatureses.com','throughoutes.net','ubiquitousing.net',
    'uiservice.cc','unbananaize.net','uncellment.com','underappoints.com','undercolorship.com',
    'undereliminatelike.com','underlengthyible.com','underlistify.com','underoriginateise.com',
    'underpainal.com','underrecognize.com','underthirdness.com','unendureify.com','unfireness.com',
    'unholdible.com','unignorantal.com','uninjureible.com','unlabors.net','unofficialest.com','unpenguin.net',
    'unrewardship.com','unstickyic.com','unswingible.net','unthinkableest.com','ununitise.net',
    'ununixize.com','unwomanal.com','vacationerably.com','vacuumtubr.net','viewfinderes.com',
    'vigilantesest.com','waistbandsable.net','winservice.cc','workplacessed.com','xenogenetications.com',
    'xenograftsized.net','yammeringsize.com','yesterdaysing.net','youthquakees.com','zinkenital.net',
    'zoosporangiaable.com'
    )
}

# ==============================================================================
# FULL host check - runs on the remote host via WinRM (read-only)
# ==============================================================================
$HuntBlock = {
    param($IOC, $DoEventLogs)
    # Literal MUST appear in this block text so PowerShell script-block logging (4104)
    # records it on the host and the event-log rule below self-excludes this hunt's own run.
    $HUNT_SENTINEL = 'HUNTSELF_7Q2X9'
    $F = New-Object System.Collections.Generic.List[object]
    $add = { param($Sev,$Cat,$Detail,$Ev)
        $F.Add([pscustomobject]@{ Severity=$Sev; Category=$Cat; Detail=$Detail; Evidence=$Ev }) }

    # --- 1) Drop dir + files ---------------------------------------------------
    $dropDir = Test-Path -LiteralPath $IOC.DropDir
    if ($dropDir) {
        & $add 'HIGH' 'Filesystem' "Drop directory present: $($IOC.DropDir)" $IOC.DropDir
        foreach ($f in $IOC.DropFiles) {
            $p = Join-Path $IOC.DropDir $f
            if (Test-Path -LiteralPath $p) {
                $it = Get-Item -LiteralPath $p -Force -EA SilentlyContinue
                $h  = try { (Get-FileHash -LiteralPath $p -Algorithm SHA256 -EA Stop).Hash } catch { 'n/a' }
                & $add 'CRITICAL' 'Filesystem' "Dropped file: $f" ("{0} | {1}B | created {2} | {3}" -f $p,$it.Length,$it.CreationTimeUtc,$h)
                if ($f -notlike '*bSSG*') {
                    try { $t = Get-Content -LiteralPath $p -Raw -EA Stop
                          $m = $IOC.ContentMarkers | Where-Object { $t -match [regex]::Escape($_) }
                          if ($m) { & $add 'CRITICAL' 'Filesystem' "Payload markers in $f" ($m -join ', ') } } catch {}
                }
            }
        }
        try { $items = @(Get-ChildItem -LiteralPath $IOC.DropDir -Force -EA Stop | Select-Object -Expand Name) -join ';'
              & $add 'HIGH' 'Filesystem' "Drop dir contents" $items } catch {}
    }
    try { Get-ChildItem 'C:\ProgramData' -Recurse -Depth 4 -Filter '*.ps1' -File -Force -EA SilentlyContinue |
            Where-Object { $_.FullName -notlike "$($IOC.DropDir)*" -and
                           $_.FullName -notlike '*\Microsoft\VisualStudio\Packages\*' -and
                           $_.FullName -notlike '*\Package Cache\*' -and
                           $_.FullName -notlike '*\Microsoft\Windows Defender\*' -and
                           $_.LastWriteTimeUtc -gt (Get-Date).AddDays(-120).ToUniversalTime() } |
            ForEach-Object { & $add 'LOW' 'Filesystem' "Other recent .ps1 under ProgramData (review)" $_.FullName }
    } catch {}

    # --- 2) Scheduled task -----------------------------------------------------
    try {
        Get-ScheduledTask -EA SilentlyContinue | ForEach-Object {
            $t = $_
            if ($t.TaskName -eq $IOC.TaskName -or $t.TaskPath -like "*$($IOC.TaskFolder1)*" -or $t.TaskPath -like "*$($IOC.TaskFolder2)*") {
                $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
                & $add 'CRITICAL' 'Persistence' "Malicious scheduled task: $($t.TaskPath)$($t.TaskName)" $act
            } else {
                foreach ($a in $t.Actions) { $cl = "$($a.Execute) $($a.Arguments)"
                    if ($cl -match 'powershell' -and $cl -match 'ProgramData' -and $cl -match '\.ps1' -and ($cl -match 'Hidden|Bypass|NoProfile')) {
                        & $add 'MEDIUM' 'Persistence' "Suspicious hidden-PS task: $($t.TaskPath)$($t.TaskName)" $cl } }
            }
        }
    } catch {}
    $tf = "C:\Windows\System32\Tasks\$($IOC.TaskFolder1)\$($IOC.TaskFolder2)\$($IOC.TaskName)"
    if (Test-Path -LiteralPath $tf) { & $add 'CRITICAL' 'Persistence' "Task definition file present" $tf }
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    foreach ($fld in @($IOC.TaskFolder1,$IOC.TaskFolder2,$IOC.TaskName)) {
        try { Get-ChildItem -Path $tree -Recurse -EA SilentlyContinue | Where-Object { $_.PSChildName -eq $fld } |
              ForEach-Object { & $add 'HIGH' 'Registry' "TaskCache tree entry: $fld" $_.Name } } catch {}
    }

    # --- 3) Live beacon process ------------------------------------------------
    try { Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA SilentlyContinue |
          Where-Object { $_.CommandLine -and ($_.CommandLine -match 'Balleticalless|unholdible') } |
          ForEach-Object { & $add 'CRITICAL' 'Process' "Running beacon PID $($_.ProcessId)" $_.CommandLine } } catch {}

    # --- 4) Network: DNS cache / hosts / active connections --------------------
    $dset = @{}; foreach ($d in $IOC.Domains) { $dset[$d.ToLower()] = $true }
    if (Get-Command Get-DnsClientCache -EA SilentlyContinue) {
        try { Get-DnsClientCache -EA SilentlyContinue | ForEach-Object {
                $e = ("$($_.Entry)").ToLower().TrimEnd('.'); $dat = "$($_.Data)"
                if ($dset[$e] -or $IOC.C2IPs -contains $dat) { & $add 'HIGH' 'Network' "C2 in DNS cache: $($_.Entry)" ("{0} -> {1}" -f $_.Entry,$_.Data) }
              } } catch {}
    }
    try { $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -EA SilentlyContinue
          foreach ($line in $hosts) { foreach ($d in $IOC.Domains) { if ($line -match [regex]::Escape($d)) { & $add 'MEDIUM' 'Network' "C2 domain in hosts file: $d" $line } }
                                      foreach ($ip in $IOC.C2IPs) { if ($line -match [regex]::Escape($ip)) { & $add 'MEDIUM' 'Network' "C2 IP in hosts file: $ip" $line } } } } catch {}
    if (Get-Command Get-NetTCPConnection -EA SilentlyContinue) {
        try { Get-NetTCPConnection -EA SilentlyContinue | Where-Object { $IOC.C2IPs -contains $_.RemoteAddress } |
              ForEach-Object { & $add 'CRITICAL' 'Network' "Active connection to C2 IP $($_.RemoteAddress):$($_.RemotePort)" ("state=$($_.State) pid=$($_.OwningProcess)") } } catch {}
    }

    # --- 5) Event logs (opt-in) ------------------------------------------------
    if ($DoEventLogs) {
        $since = (Get-Date).AddDays(-45)
        try { Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=$since } -EA SilentlyContinue |
              Where-Object { $_.Message -match 'Undraftment|Unlearningest|Lengthwisization' } | Select-Object -First 20 |
              ForEach-Object { & $add 'HIGH' 'EventLog' "TaskScheduler evt $($_.Id) @ $($_.TimeCreated)" (($_.Message -split "`n")[0]) } } catch {}
        $tokRe = ($IOC.LogTokens | ForEach-Object { [regex]::Escape($_) }) -join '|'
        try { Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$since } -EA SilentlyContinue |
              Where-Object { $_.Message -notmatch $HUNT_SENTINEL -and $_.Message -match $tokRe } | Select-Object -First 20 |
              ForEach-Object { & $add 'HIGH' 'EventLog' "PS ScriptBlock 4104 @ $($_.TimeCreated)" (($_.Message -split "`n")[0]) } } catch {}
        try { Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$since } -EA SilentlyContinue |
              Where-Object { ($_.Id -eq 11 -and $_.Message -match 'Balleticalless') -or
                             ($_.Id -eq 22 -and $_.Message -match 'rescrewify|vacuumtubr|refictionify|keelhaulably') -or
                             ($_.Id -eq 1  -and $_.Message -match 'unholdible|Balleticalless') } | Select-Object -First 20 |
              ForEach-Object { & $add 'HIGH' 'EventLog' "Sysmon evt $($_.Id) @ $($_.TimeCreated)" (($_.Message -split "`n")[0]) } } catch {}
        try { Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$since } -EA SilentlyContinue |
              Where-Object { $_.Message -match 'powershell' -and ($_.Message -match 'Balleticalless|unholdible' -or ($_.Message -match 'gcm' -and $_.Message -match 'minimize')) } | Select-Object -First 20 |
              ForEach-Object { & $add 'HIGH' 'EventLog' "Security 4688 @ $($_.TimeCreated)" (($_.Message -split "`n")[0]) } } catch {}
    }

    $sev = $F.Severity
    $verdict = if ($sev -contains 'CRITICAL' -or $sev -contains 'HIGH') { 'INFECTED' }
               elseif ($sev -contains 'MEDIUM') { 'SUSPICIOUS' }
               elseif ($sev -contains 'LOW')    { 'REVIEW' }
               else                             { 'CLEAN' }
    [pscustomobject]@{ ComputerName=$env:COMPUTERNAME; Verdict=$verdict; Coverage='FULL'
                       Channel='WinRM'; FindingCount=$F.Count; Findings=$F.ToArray()
                       ScannedUtc=(Get-Date).ToUniversalTime().ToString('s') }
}

# ==============================================================================
# SMB fallback worker - runs LOCALLY, reaches remote over \\host\C$ (files only)
# ==============================================================================
$SmbWorker = {
    param($Computer, $Credential, $IOC, $TcpTimeoutMs)
    function Test-Port { param($H,$P,$T)
        $c=$null; try { $c=New-Object Net.Sockets.TcpClient
            $a=$c.BeginConnect($H,$P,$null,$null)
            if(-not $a.AsyncWaitHandle.WaitOne($T,$false)){$c.Close();return $false}
            $c.EndConnect($a); $ok=$c.Connected; $c.Close(); return $ok } catch { if($c){try{$c.Close()}catch{}}; return $false } }

    $mk = { param($Verdict,$Coverage,$Detail,$Findings)
        [pscustomobject]@{ ComputerName=$Computer; Verdict=$Verdict; Coverage=$Coverage; Channel='SMB'
                           FindingCount=@($Findings).Count; Findings=@($Findings)
                           ScannedUtc=(Get-Date).ToUniversalTime().ToString('s'); Detail=$Detail } }

    if (-not (Test-Port $Computer 445 $TcpTimeoutMs)) { return & $mk 'UNREACHABLE' 'NONE' '445 closed' @() }

    $drv = 'IOC' + [Guid]::NewGuid().ToString('N').Substring(0,6)
    $F = New-Object System.Collections.Generic.List[object]
    $add = { param($Sev,$Cat,$Detail,$Ev) $F.Add([pscustomobject]@{Severity=$Sev;Category=$Cat;Detail=$Detail;Evidence=$Ev}) }
    try {
        $np = @{ Name=$drv; PSProvider='FileSystem'; Root="\\$Computer\C`$"; ErrorAction='Stop' }
        if ($Credential) { $np.Credential = $Credential }
        New-PSDrive @np | Out-Null
        $root = "${drv}:"
        $dir  = "$root\ProgramData\Balleticalless"
        if (Test-Path -LiteralPath $dir) {
            & $add 'HIGH' 'Filesystem' "Drop directory present (SMB)" "\\$Computer\C`$\ProgramData\Balleticalless"
            foreach ($f in $IOC.DropFiles) { $p="$dir\$f"
                if (Test-Path -LiteralPath $p) {
                    $h = try { (Get-FileHash -LiteralPath $p -Algorithm SHA256 -EA Stop).Hash } catch { 'n/a' }
                    & $add 'CRITICAL' 'Filesystem' "Dropped file: $f (SMB)" ("$p | $h") } }
            try { $items=@(Get-ChildItem -LiteralPath $dir -Force -EA Stop|Select-Object -Expand Name) -join ';'
                  & $add 'HIGH' 'Filesystem' "Drop dir contents (SMB)" $items } catch {}
        }
        $tf = "$root\Windows\System32\Tasks\$($IOC.TaskFolder1)\$($IOC.TaskFolder2)\$($IOC.TaskName)"
        if (Test-Path -LiteralPath $tf) { & $add 'CRITICAL' 'Persistence' "Task definition file present (SMB)" $tf }
        try { $hosts = Get-Content "$root\Windows\System32\drivers\etc\hosts" -EA SilentlyContinue
              foreach ($line in $hosts) { foreach ($d in $IOC.Domains) { if ($line -match [regex]::Escape($d)) { & $add 'MEDIUM' 'Network' "C2 domain in hosts file: $d (SMB)" $line } } } } catch {}
    } catch {
        return & $mk 'UNREACHABLE' 'NONE' ("SMB: " + $_.Exception.Message) @()
    } finally { try { Remove-PSDrive -Name $drv -Force -EA SilentlyContinue } catch {} }

    $sev=$F.Severity
    $verdict = if ($sev -contains 'CRITICAL' -or $sev -contains 'HIGH') { 'INFECTED' }
               elseif ($sev -contains 'MEDIUM') { 'SUSPICIOUS' }
               elseif ($sev -contains 'LOW')    { 'REVIEW' }
               else                             { 'CLEAN_PARTIAL' }
    & $mk $verdict 'PARTIAL' 'files+task+hosts only; registry/process/DNS/logs NOT checked' $F.ToArray()
}

# ==============================================================================
# Resolve targets
# ==============================================================================
$ScriptV = ($ScriptVersion -replace '\s.*$','')
Write-Host ""; Write-Rule -Color Cyan
Write-Host ("  Hunt-ClickFix-Compromise   v{0}" -f $ScriptV) -ForegroundColor White
Write-Host  "  Tabby ClickFix/Citrix incident - evidence-of-compromise sweep (read-only)" -ForegroundColor Gray
Write-Rule -Color Cyan

$targets = @()
switch ($PSCmdlet.ParameterSetName) {
    'Local' { $targets = @($env:COMPUTERNAME) }
    'List'  { $targets = $ComputerName }
    'File'  { $targets = Get-Content -LiteralPath $ComputerListFile | Where-Object { $_.Trim() } }
    'AD'    {
        if (-not $FromAD) { Write-Host "  Specify -Local, -ComputerName, -ComputerListFile, or -FromAD." -ForegroundColor Yellow; return }
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -EA Stop
            $ap = @{ Filter='Enabled -eq $true'; Properties='DNSHostName,OperatingSystem' }
            if ($SearchBase) { $ap.SearchBase = $SearchBase }
            $targets = Get-ADComputer @ap | Where-Object { $_.OperatingSystem -match 'Windows' -or -not $_.OperatingSystem } |
                       ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
        } else {
            Write-Host "  [*] ActiveDirectory module absent; enumerating via LDAP/ADSI ..." -ForegroundColor DarkGray
            try {
                $rootPath = if ($SearchBase) { "LDAP://$SearchBase" } else { $r=[ADSI]"LDAP://RootDSE"; "LDAP://$($r.defaultNamingContext)" }
                $ds = New-Object System.DirectoryServices.DirectorySearcher (New-Object System.DirectoryServices.DirectoryEntry($rootPath))
                $ds.Filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
                $ds.PageSize = 1000; [void]$ds.PropertiesToLoad.Add('dnshostname'); [void]$ds.PropertiesToLoad.Add('name')
                $targets = foreach ($e in $ds.FindAll()) {
                    if ($e.Properties['dnshostname'].Count) { [string]$e.Properties['dnshostname'][0] }
                    elseif ($e.Properties['name'].Count)    { [string]$e.Properties['name'][0] } }
            } catch { throw "AD enumeration failed (module absent, LDAP errored): $($_.Exception.Message)" }
        }
    }
}
$targets = $targets | Where-Object { $_ } | Select-Object -Unique
if (-not $targets) { Write-Host "  No targets resolved." -ForegroundColor Yellow; return }

Write-Host ("  Targets : {0}   EventLogs: {1}   SMB-fallback: {2}   Output: {3}" -f `
    $targets.Count, $(if($IncludeEventLogs){'ON'}else{'off'}), $(if($NoSmbFallback){'off'}else{'ON'}), $OutputDirectory) -ForegroundColor DarkGray
Write-Host ""

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$results = New-Object System.Collections.Generic.List[object]
$tally   = [ordered]@{ INFECTED=0; SUSPICIOUS=0; REVIEW=0; CLEAN=0; CLEAN_PARTIAL=0; UNREACHABLE=0; EXPECTED_HIT=0 }
$sw      = [System.Diagnostics.Stopwatch]::StartNew()

$emit = {
    param($res)
    $short = ("$($res.ComputerName)").Split('.')[0].ToUpperInvariant()
    if ($res.Verdict -eq 'INFECTED' -and ($ExpectedTestHosts | ForEach-Object { $_.ToUpperInvariant() }) -contains $short) { $res.Verdict = 'EXPECTED_HIT' }
    $results.Add($res)
    if ($tally.Contains($res.Verdict)) { $tally[$res.Verdict]++ } else { $tally[$res.Verdict]=1 }
    if ($res.Verdict -in 'INFECTED','SUSPICIOUS','REVIEW','EXPECTED_HIT') {
        Write-Host ("  {0}  {1,-26}  {2}  {3} finding(s)" -f $VTag[$res.Verdict],$res.ComputerName,$res.Channel,$res.FindingCount) -ForegroundColor $VColor[$res.Verdict] }
}

# ==============================================================================
# PASS 1 - WinRM (FULL)
# ==============================================================================
$selfNames = @($env:COMPUTERNAME,'localhost','.',"$env:COMPUTERNAME.$env:USERDNSDOMAIN")
$remote = @($targets | Where-Object { $selfNames -notcontains $_ })
$self   = @($targets | Where-Object { $selfNames -contains $_ })
$winrmDone = @{}

if ($self) { $r = & $HuntBlock $IOC $IncludeEventLogs.IsPresent; & $emit $r }

if ($remote) {
    $expected=$remote.Count; $done=0
    $ic = @{ ComputerName=$remote; ScriptBlock=$HuntBlock; ArgumentList=@($IOC,$IncludeEventLogs.IsPresent)
             ThrottleLimit=$ThrottleLimit; ErrorAction='SilentlyContinue'; ErrorVariable='winrmErr' }
    if ($Credential) { $ic.Credential = $Credential }
    # Fail fast on WinRM-filtered hosts (-> SMB fallback) but allow slow event-log queries to finish.
    $ic.SessionOption = New-PSSessionOption -OpenTimeout 4000 -OperationTimeout 120000 -NoMachineProfile
    Write-Host "  [*] Pass 1: WinRM ..." -ForegroundColor DarkGray
    Invoke-Command @ic | ForEach-Object {
        $done++
        # PSComputerName == the exact -ComputerName value Invoke-Command was given (reliable key)
        $tgt = if ($_.PSComputerName) { "$($_.PSComputerName)" } else { "$($_.ComputerName)" }
        $winrmDone[$tgt.ToLower()] = $true
        & $emit $_
        $flag = $tally.INFECTED + $tally.SUSPICIOUS + $tally.REVIEW + $tally.EXPECTED_HIT
        Write-Progress -Activity 'ClickFix sweep - WinRM' -Status ("{0}/{1}  clean {2}  flagged {3}  {4:mm\:ss}" -f $done,$expected,$tally.CLEAN,$flag,$sw.Elapsed) -PercentComplete ([int](($done/[math]::Max($expected,1))*100)) -CurrentOperation $_.ComputerName
    }
    Write-Progress -Activity 'ClickFix sweep - WinRM' -Completed
}

# hosts that failed WinRM -> SMB fallback candidates (exact-target match, no double-count)
$fbCandidates = @($remote | Where-Object { -not $winrmDone[$_.ToLower()] })

# ==============================================================================
# PASS 2 - SMB C$ fallback (PARTIAL), parallel via runspace pool
# ==============================================================================
if ($fbCandidates.Count -gt 0 -and -not $NoSmbFallback) {
    Write-Host ("  [*] Pass 2: SMB fallback for {0} WinRM-unreachable host(s) ..." -f $fbCandidates.Count) -ForegroundColor DarkGray
    $pool = [RunspaceFactory]::CreateRunspacePool(1,$SmbThrottle); $pool.Open()
    $jobs = @()
    foreach ($c in $fbCandidates) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
        $null = $ps.AddScript($SmbWorker.ToString()).AddArgument($c).AddArgument($Credential).AddArgument($IOC).AddArgument($TcpTimeoutMs)
        $jobs += [pscustomobject]@{ C=$c; PS=$ps; H=$ps.BeginInvoke() }
    }
    $fdone=0; $ftot=$jobs.Count
    foreach ($j in $jobs) {
        try { $r = @($j.PS.EndInvoke($j.H)) | Select-Object -Last 1; if ($r) { & $emit $r } }
        catch { & $emit ([pscustomobject]@{ ComputerName=$j.C; Verdict='UNREACHABLE'; Coverage='NONE'; Channel='SMB'; FindingCount=0; Findings=@(); ScannedUtc=(Get-Date).ToUniversalTime().ToString('s') }) }
        finally { $j.PS.Dispose() }
        $fdone++; Write-Progress -Activity 'ClickFix sweep - SMB fallback' -Status ("{0}/{1}" -f $fdone,$ftot) -PercentComplete ([int](($fdone/[math]::Max($ftot,1))*100))
    }
    Write-Progress -Activity 'ClickFix sweep - SMB fallback' -Completed
    $pool.Close(); $pool.Dispose()
} elseif ($fbCandidates.Count -gt 0) {
    foreach ($c in $fbCandidates) { & $emit ([pscustomobject]@{ ComputerName=$c; Verdict='UNREACHABLE'; Coverage='NONE'; Channel='NONE'; FindingCount=0; Findings=@(); ScannedUtc=(Get-Date).ToUniversalTime().ToString('s') }) }
}
$sw.Stop()

# ==============================================================================
# Report
# ==============================================================================
$order = @{ INFECTED=0; EXPECTED_HIT=1; SUSPICIOUS=2; REVIEW=3; CLEAN_PARTIAL=4; UNREACHABLE=5; CLEAN=6 }
$sorted = @($results | Sort-Object @{ Expression={ $order[$_.Verdict] } }, ComputerName)
$total  = [math]::Max($results.Count,1)

Write-Host ""; Write-Rule -Color Cyan
Write-Host ("  SWEEP COMPLETE    {0} host(s)    elapsed {1:mm\:ss}" -f $results.Count,$sw.Elapsed) -ForegroundColor White
Write-Rule -Color Cyan
foreach ($v in 'INFECTED','EXPECTED_HIT','SUSPICIOUS','REVIEW','CLEAN','CLEAN_PARTIAL','UNREACHABLE') {
    $n=@($results|Where-Object{$_.Verdict -eq $v}).Count
    Write-Host ("  {0,-14} {1,4}  {2}  {3,5}%" -f $v,$n,(Get-Bar $n $total 22),[math]::Round(($n/$total)*100,1)) -ForegroundColor $VColor[$v]
}
# coverage note
$fullyChecked = @($results | Where-Object { $_.Verdict -in 'INFECTED','EXPECTED_HIT','SUSPICIOUS','REVIEW','CLEAN' }).Count
Write-Host ("  Definitive coverage (fully assessed): {0}%" -f [math]::Round(($fullyChecked/$total)*100,1)) -ForegroundColor Cyan

$flagged = @($sorted | Where-Object { $_.Verdict -in 'INFECTED','EXPECTED_HIT','SUSPICIOUS','REVIEW' })
if ($flagged.Count) {
    Write-Host ""; Write-Host "  FLAGGED HOSTS" -ForegroundColor White; Write-Rule -Ch ([string][char]0x2500) -Color DarkGray
    foreach ($r in $flagged) {
        Write-Host ("  {0}  {1}   ({2})" -f $VTag[$r.Verdict],$r.ComputerName,$r.Channel) -ForegroundColor $VColor[$r.Verdict]
        foreach ($f in ($r.Findings | Sort-Object @{ Expression={ @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3}[$_.Severity] } })) {
            $sc = if ($SColor.Contains([string]$f.Severity)) { $SColor[[string]$f.Severity] } else { 'Gray' }
            Write-Host ("      {0,-9} {1,-12} {2}" -f $f.Severity,$f.Category,$f.Detail) -ForegroundColor $sc
            if ($f.Evidence) { Write-Host ("        {0}{1}" -f $Glyph.Arrow,$f.Evidence) -ForegroundColor DarkGray }
        }
        Write-Host ""
    }
} else { Write-Host ""; Write-Host "  No hosts flagged among assessed systems." -ForegroundColor Green }

# ==============================================================================
# Export
# ==============================================================================
if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$csv  = Join-Path $OutputDirectory "ClickFixSweep_$stamp.csv"
$json = Join-Path $OutputDirectory "ClickFixSweep_$stamp.json"
$hits = Join-Path $OutputDirectory "ClickFixSweep_HITS_$stamp.csv"

$flat = $sorted | ForEach-Object { $r=$_
    if ($r.Findings.Count) { foreach ($f in $r.Findings) { [pscustomobject]@{ ComputerName=$r.ComputerName; Verdict=$r.Verdict; Coverage=$r.Coverage; Channel=$r.Channel; Severity=$f.Severity; Category=$f.Category; Detail=$f.Detail; Evidence=$f.Evidence; ScannedUtc=$r.ScannedUtc } } }
    else { [pscustomobject]@{ ComputerName=$r.ComputerName; Verdict=$r.Verdict; Coverage=$r.Coverage; Channel=$r.Channel; Severity=''; Category=''; Detail=''; Evidence=''; ScannedUtc=$r.ScannedUtc } } }
$flat | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
$flat | Where-Object { $_.Verdict -in 'INFECTED','EXPECTED_HIT','SUSPICIOUS','REVIEW' } | Export-Csv -LiteralPath $hits -NoTypeInformation -Encoding UTF8
$sorted | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $json -Encoding UTF8

Write-Host ""; Write-Rule -Ch ([string][char]0x2500) -Color DarkGray
Write-Host ("  Full CSV : {0}" -f $csv)  -ForegroundColor Green
Write-Host ("  Hits CSV : {0}" -f $hits) -ForegroundColor Green
Write-Host ("  JSON     : {0}" -f $json) -ForegroundColor Green
Write-Rule -Ch ([string][char]0x2500) -Color DarkGray
