param(
    [ValidateSet('Quiet', 'Verbose')]
    [string]$V = 'Quiet',    # Set verbosity level using -V parameter
    [switch]$Help              # Display help message using -Help parameter
)

if ($Help) {
    Write-Host @"
Usage: .\UBHEX.ps1 [-V Quiet|Verbose] [-Help]

Parameters:
 -V        Set verbosity level ('Quiet' or 'Verbose'). Default is 'Quiet'.
 -Help     Display this help message.

Description:
This script analyzes user activity by aggregating data from multiple sources:
1. File access and modification times within user directories.
2. Browser usage metadata (last modified times of history files).
3. User's scheduled tasks execution history.
4. Windows Event Logs (Logon/Logoff events and Workstation Lock/Unlock events).
5. Registry Analysis (Recent Documents and Startup Programs).
6. Sync Folders Activity (OneDrive, Dropbox, Google Drive).

It generates a consolidated summary of user activity periods and detailed analyses,
including average start time and end time per day.

Examples:
 .\UBHEX.ps1 -V Quiet     # Runs the script in quiet mode
 .\UBHEX.ps1 -V Verbose   # Runs the script with detailed output
 .\UBHEX.ps1 -Help        # Displays this help message
"@
    exit
}

# Define the time range (e.g., last 60 days)
$DaysToAnalyze = 60
$EndTime = Get-Date
$StartTime = $EndTime.AddDays(-$DaysToAnalyze)

$CurrentUser = $env:USERNAME

$TimeZone = [System.TimeZoneInfo]::Local

# Define the directories to monitor for file access/modification
$directories = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    [Environment]::GetFolderPath("Desktop"),
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming"
)

# Define browser history file paths using a hashtable for clear association
$browserHistories = @{
    'Chrome'  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    'Edge'    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    'Firefox' = "$env:APPDATA\Mozilla\Firefox\Profiles\*default*\places.sqlite"
}

# Define sync folders to analyze
$syncFolders = @(
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\Dropbox",
    "$env:USERPROFILE\Google Drive",
    "$env:USERPROFILE\Drive"
)

switch ($V) {
    'Quiet' {
        $VerbosePreference = 'SilentlyContinue'
        $InformationPreference = 'SilentlyContinue'
    }
    'Verbose' {
        $VerbosePreference = 'Continue'
        $InformationPreference = 'Continue'
    }
}

Write-Information "Starting UBHEX for user: $CurrentUser"

$activityTimestamps = [System.Collections.Generic.List[DateTime]]::new()
$lockedPeriods = [System.Collections.Generic.List[Hashtable]]::new()

function Check-SecurityTools {
    Write-Verbose "Checking for security tools..."
    $securityTools = @('MsMpEng', 'sense', 'CylanceSvc', 'CarbonBlack', 'CrowdStrike', 'SentinelOne')
    $runningTools = @()

    foreach ($tool in $securityTools) {
        if (Get-Process -Name $tool -ErrorAction SilentlyContinue) {
            $runningTools += $tool
        }
    }

    return $runningTools
}

$securityToolsDetected = Check-SecurityTools
if ($securityToolsDetected.Count -gt 0) {
    Write-Host "Security tools : $($securityToolsDetected -join ', '). Entering low-profile mode..." -ForegroundColor Yellow
    $LowProfileMode = $true
} else {
    Write-Verbose "No security tools detected."
    $LowProfileMode = $false
}

Write-Verbose "Performing Pre-Run System Load Check..."
$cpuUsage = Get-WmiObject win32_processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
$availableMemory = (Get-WmiObject -Class Win32_OperatingSystem).FreePhysicalMemory / 1MB
$totalMemory = (Get-WmiObject -Class Win32_OperatingSystem).TotalVisibleMemorySize / 1MB

$memoryUsagePercentage = (($totalMemory - $availableMemory) / $totalMemory) * 100

if ($cpuUsage -gt 80 -or $memoryUsagePercentage -gt 75) {
    Write-Host "System load is high (CPU usage: $cpuUsage%, Memory usage: ${memoryUsagePercentage}%). Exiting to avoid resource contention." -ForegroundColor Yellow
    exit
}

function Get-SafeFiles {
    param (
        [string]$Path,
        [string[]]$ExcludeDirs
    )

    try {
        # Retrieve all subdirectories, excluding specified directories
        $subDirs = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | Where-Object {
            $ExcludeDirs -notcontains $_.Name
        }

        foreach ($dir in $subDirs) {
            # Recursive call to traverse subdirectories
            Get-SafeFiles -Path $dir.FullName -ExcludeDirs $ExcludeDirs
        }
    }
    catch {
        Write-Verbose "Access denied or error accessing directory: $Path. Skipping."
    }

    try {
        Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue | Where-Object {
            ($_.LastAccessTime -ge $StartTime -and $_.LastAccessTime -le $EndTime) -or
            ($_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime)
        } | ForEach-Object {
            $activityTimestamps.Add([System.TimeZoneInfo]::ConvertTime($_.LastAccessTime, $TimeZone))
            $activityTimestamps.Add([System.TimeZoneInfo]::ConvertTime($_.LastWriteTime, $TimeZone))
        }
    }
    catch {
        Write-Verbose "Access denied or error accessing files in: $Path. Skipping."
    }
}

function Analyze-SyncFolders {
    param (
        [string[]]$Folders
    )

    Write-Verbose "[4] Analyzing Sync Folders Activity..."

    foreach ($folder in $Folders) {
        if (Test-Path $folder) {
            Write-Verbose "Scanning sync folder: $folder"
            try {
                Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                    $_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime
                } | ForEach-Object {
                    $timestamp = [System.TimeZoneInfo]::ConvertTime($_.LastWriteTime, $TimeZone)
                    $activityTimestamps.Add($timestamp)
                }
            }
            catch {
                Write-Verbose "Error accessing files in sync folder: $folder. Skipping."
            }
        }
        else {
            Write-Verbose "Sync folder not found: $folder"
        }
    }
}

function Analyze-LockUnlockEvents {
    param (
        [datetime]$StartTime,
        [datetime]$EndTime,
        [System.Collections.Generic.List[Hashtable]]$LockedPeriods
    )

    Write-Verbose "[5] Analyzing Lock and Unlock Events..."

    
    $lockEventID = 4800
    $unlockEventID = 4801
    $userSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    $eventFilter = @"
*[
    System[
        (EventID=$lockEventID or EventID=$unlockEventID)
        and TimeCreated[@SystemTime >= '$($StartTime.ToUniversalTime().ToString("o"))']
        and TimeCreated[@SystemTime <= '$($EndTime.ToUniversalTime().ToString("o"))']
    ]
    and
    EventData[
        Data[@Name='TargetUserSid']='$userSID'
    ]
]
"@

    try {
        $events = Get-WinEvent -FilterXPath $eventFilter -LogName 'Security' -ErrorAction SilentlyContinue

        Write-Verbose "Collected $($events.Count) Lock/Unlock events."

        $lockStack = New-Object System.Collections.Stack

        foreach ($event in $events) {
            $eventID = $event.Id
            $timestamp = [System.TimeZoneInfo]::ConvertTime($event.TimeCreated, $TimeZone)

            if ($eventID -eq $lockEventID) {

                $lockStack.Push($timestamp)
            }
            elseif ($eventID -eq $unlockEventID) {
                if ($lockStack.Count -gt 0) {
                    $lockTime = $lockStack.Pop()
                    $unlockTime = $timestamp

                    
                    $LockedPeriods.Add(@{
                        'LockTime' = $lockTime
                        'UnlockTime' = $unlockTime
                    })
                }
                else {
                    Write-Verbose "Unmatched unlock event at $timestamp"
                }
            }
        }

        while ($lockStack.Count -gt 0) {
            $lockTime = $lockStack.Pop()
            $LockedPeriods.Add(@{
                'LockTime' = $lockTime
                'UnlockTime' = $EndTime # Assume unlock at the end of the analysis period
            })
        }
    }
    catch {
        Write-Verbose "Error retrieving Lock/Unlock events: $_"
    }
    finally {
        if ($events) { $events = $null }
    }
}

function Analyze-EventLogs {
    param (
        [datetime]$StartTime,
        [datetime]$EndTime,
        [System.Collections.Generic.List[datetime]]$ActivityTimestamps
    )

    Write-Verbose "[6] Analyzing Logon and Logoff Events..."


    $logonEventID = 4624
    $logoffEventID = 4634
    $userSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $eventFilter = @"
*[
    System[
        (EventID=$logonEventID or EventID=$logoffEventID)
        and TimeCreated[@SystemTime >= '$($StartTime.ToUniversalTime().ToString("o"))']
        and TimeCreated[@SystemTime <= '$($EndTime.ToUniversalTime().ToString("o"))']
    ]
    and
    EventData[
        Data[@Name='TargetUserSid']='$userSID'
    ]
]
"@

    try {
        $events = Get-WinEvent -FilterXPath $eventFilter -LogName 'Security' -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $ActivityTimestamps.Add([System.TimeZoneInfo]::ConvertTime($event.TimeCreated, $TimeZone))
        }

        Write-Verbose "Collected $($events.Count) Logon/Logoff events."
    }
    catch {
        Write-Verbose "Error retrieving Logon/Logoff events: $_"
    }
    finally {
        if ($events) { $events = $null }
    }
}

function Analyze-Registry {
    param (
        [System.Collections.Generic.List[datetime]]$ActivityTimestamps
    )

    Write-Verbose "[7] Analyzing Registry for Recent Activities..."

    $recentDocsKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    try {
        Get-ChildItem -Path $recentDocsKey -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.LastWriteTime -ge $StartTime -and $_.LastWriteTime -le $EndTime) {
                $ActivityTimestamps.Add([System.TimeZoneInfo]::ConvertTime($_.LastWriteTime, $TimeZone))
            }
        }
        Write-Verbose "Collected recent document activity from registry."
    }
    catch {
        Write-Verbose "Error accessing RecentDocs registry key: $_"
    }

    $startupKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    try {
        Get-ItemProperty -Path $startupKey -ErrorAction SilentlyContinue | ForEach-Object {
            $ActivityTimestamps.Add([System.TimeZoneInfo]::ConvertTime((Get-Date), $TimeZone))
        }
        Write-Verbose "Collected startup program activity from registry."
    }
    catch {
        Write-Verbose "Error accessing Run registry key: $_"
    }
}

Write-Verbose "[1] Monitoring File Access and Modification Times..."

$excludeDirs = @(
    'My Music',
    'My Pictures',
    'My Videos',
    'Application Data',
    'System Volume Information',
    'ProgramData',
    'History',
    'INetCache',
    'Content.IE5',
    'Low',
    'Temporary Internet Files',
    'WinSAT'
)

foreach ($dir in $directories) {
    if (Test-Path $dir) {
        Write-Verbose "Scanning directory: $dir"
        Get-SafeFiles -Path $dir -ExcludeDirs $excludeDirs
    }
    else {
        Write-Verbose "Directory not found or inaccessible: $dir"
    }
}

Write-Verbose "Collected $($activityTimestamps.Count) file access/modification timestamps."

Write-Verbose "[2] Analyzing Browser Activity..."

$browserUsage = @{}

foreach ($browser in $browserHistories.Keys) {
    $historyPath = $browserHistories[$browser]
    Write-Verbose "Processing $browser Browser..."

    if ($browser -eq 'Firefox') {
        # Handle Firefox with multiple profiles
        $profilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles\"
        try {
            $profiles = Get-ChildItem -Path $profilesPath -Directory -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "Firefox profiles not found or inaccessible."
            continue
        }

        foreach ($profile in $profiles) {
            $placesDb = "$($profile.FullName)\places.sqlite"
            if (Test-Path $placesDb) {
                try {
                    $fileInfo = Get-Item $placesDb -ErrorAction SilentlyContinue
                    if ($fileInfo.LastWriteTime -ge $StartTime -and $fileInfo.LastWriteTime -le $EndTime) {
                        $timestamp = [System.TimeZoneInfo]::ConvertTime($fileInfo.LastWriteTime, $TimeZone)
                        $activityTimestamps.Add($timestamp)

                        # Calculate usage per day
                        $activityDate = $timestamp.Date
                        if (-not $browserUsage.ContainsKey($activityDate)) {
                            $browserUsage[$activityDate] = @()
                        }
                        $browserUsage[$activityDate] += $timestamp
                    }
                }
                catch {
                    continue
                }
            }
            else {
                continue
            }
        }
    }
    else {
        # Chrome and Edge have single history files
        if (Test-Path $historyPath) {
            try {
                $fileInfo = Get-Item $historyPath -ErrorAction SilentlyContinue
                if ($fileInfo.LastWriteTime -ge $StartTime -and $fileInfo.LastWriteTime -le $EndTime) {
                    $timestamp = [System.TimeZoneInfo]::ConvertTime($fileInfo.LastWriteTime, $TimeZone)
                    $activityTimestamps.Add($timestamp)

                    # Calculate usage per day
                    $activityDate = $timestamp.Date
                    if (-not $browserUsage.ContainsKey($activityDate)) {
                        $browserUsage[$activityDate] = @()
                    }
                    $browserUsage[$activityDate] += $timestamp
                }
            }
            catch {
                continue
            }
        }
        else {
            continue
        }
    }
}

$averageBrowserUsagePerDay = @()

foreach ($date in $browserUsage.Keys) {
    $times = $browserUsage[$date] | Sort-Object
    if ($times.Count -gt 1) {
        $startTime = $times[0]
        $endTime = $times[-1]
        $duration = ($endTime - $startTime).TotalHours
        $averageBrowserUsagePerDay += $duration
    }
    elseif ($times.Count -eq 1) {
        # Assume a minimal usage duration if only one activity time is recorded
        $averageBrowserUsagePerDay += 0.2
    }
}

if ($averageBrowserUsagePerDay.Count -gt 0) {
    $averageUsage = [math]::Round(($averageBrowserUsagePerDay | Measure-Object -Average).Average, 2)
    Write-Verbose "Average Browser Usage per Day: $averageUsage hours"
}

Write-Verbose "[3] Analyzing User's Scheduled Tasks..."

# Retrieve all scheduled tasks owned by the current user
try {
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.UserId -eq "$env:USERDOMAIN\$CurrentUser" }
}
catch {
    Write-Verbose "Error retrieving scheduled tasks: $_"
    $allTasks = @()
}

if ($allTasks.Count -gt 0) {
    # Extract LastRunTime for each task
    $allTasks | ForEach-Object {
        $runTime = $_.LastRunTime
        if ($runTime -ne $null -and $runTime -ge $StartTime -and $runTime -le $EndTime) {
            $activityTimestamps.Add([System.TimeZoneInfo]::ConvertTime($runTime, $TimeZone))
        }
    }
    Write-Verbose "Collected scheduled task run timestamps."
}

Write-Verbose "Total Activity Timestamps Collected: $($activityTimestamps.Count)"

# Analyze Sync Folders Activity
Analyze-SyncFolders -Folders $syncFolders

# Analyze Lock and Unlock Events
Analyze-LockUnlockEvents -StartTime $StartTime -EndTime $EndTime -LockedPeriods $lockedPeriods

# Analyze Logon and Logoff Events
Analyze-EventLogs -StartTime $StartTime -EndTime $EndTime -ActivityTimestamps $activityTimestamps

# Analyze Registry for Recent Activities
Analyze-Registry -ActivityTimestamps $activityTimestamps

Write-Verbose "Total Activity Timestamps Collected after Event Logs and Registry Analysis: $($activityTimestamps.Count)"

Write-Verbose "[8] Consolidating Activity Periods..."

if ($activityTimestamps.Count -gt 0) {
    # Remove timestamps that fall within locked periods
    if ($lockedPeriods.Count -gt 0) {
        Write-Verbose "Excluding activity during locked periods..."
        $filteredActivityTimes = $activityTimestamps | Where-Object {
            $timestamp = $_
            $isLocked = $false
            foreach ($period in $lockedPeriods) {
                if ($timestamp -ge $period.LockTime -and $timestamp -le $period.UnlockTime) {
                    $isLocked = $true
                    break
                }
            }
            -not $isLocked
        }
    }
    else {
        $filteredActivityTimes = $activityTimestamps
    }

    $sortedActivityTimes = $filteredActivityTimes | Sort-Object

    if ($sortedActivityTimes.Count -eq 0) {
        Write-Information "No activity timestamps after excluding locked periods."
        exit
    }

    $overallStart = $sortedActivityTimes | Select-Object -First 1
    $overallEnd = $sortedActivityTimes | Select-Object -Last 1

    Write-Information "`n--- Consolidated Activity Summary ---"
    Write-Information "Overall Activity Period: $overallStart to $overallEnd"

    $activeDates = $sortedActivityTimes | ForEach-Object { $_.Date } | Sort-Object -Unique
    $totalActiveDays = $activeDates.Count

    Write-Information "Total Active Days: $totalActiveDays"
}
else {
    Write-Information "No activity timestamps collected within the specified time range."
    exit
}

# Dispose of activity timestamps list to free up memory
$activityTimestamps.TrimExcess()
$activityTimestamps = $null

Write-Verbose "[9] Analyzing Days of the Week Active..."

# Group activity timestamps by day of the week
$daysOfWeekActive = $sortedActivityTimes | Group-Object { $_.DayOfWeek } | Sort-Object Name

$dayDurations = @{}
$dayCounts = @{}
$dayStartTimes = @{}
$dayEndTimes = @{}

foreach ($dow in $daysOfWeekActive) {
    $dayName = $dow.Name
    $activityCount = $dow.Count

    $times = $dow.Group | Sort-Object
    $dayDates = $times | ForEach-Object { $_.Date } | Sort-Object -Unique
    $totalDuration = [TimeSpan]::Zero
    $startTimesList = @()
    $endTimesList = @()

    foreach ($date in $dayDates) {
        $dayTimes = $times | Where-Object { $_.Date -eq $date }
        $startTime = $dayTimes[0]
        $endTime = $dayTimes[-1]
        $duration = $endTime - $startTime
        $totalDuration += $duration

        $startTimesList += $startTime.TimeOfDay.TotalSeconds
        $endTimesList += $endTime.TimeOfDay.TotalSeconds
    }

    if ($dayDates.Count -gt 0) {
        $averageDuration = [TimeSpan]::FromTicks([long]($totalDuration.Ticks / $dayDates.Count))

        # Calculate average start and end times
        $averageStartSeconds = ($startTimesList | Measure-Object -Average).Average
        $averageEndSeconds = ($endTimesList | Measure-Object -Average).Average

        $averageStartTimeSpan = [TimeSpan]::FromSeconds($averageStartSeconds)
        $averageEndTimeSpan = [TimeSpan]::FromSeconds($averageEndSeconds)

        $formattedAverageStartTime = $averageStartTimeSpan.ToString("hh\:mm")
        $formattedAverageEndTime = $averageEndTimeSpan.ToString("hh\:mm")
    } else {
        $averageDuration = [TimeSpan]::Zero
        $formattedAverageStartTime = "N/A"
        $formattedAverageEndTime = "N/A"
    }

    $dayDurations[$dayName] = $averageDuration
    $dayCounts[$dayName] = $dayDates.Count
    $dayStartTimes[$dayName] = $formattedAverageStartTime
    $dayEndTimes[$dayName] = $formattedAverageEndTime
}

# Maximum Consecutive Active Days
$sortedActiveDates = $activeDates | Sort-Object
$consecutiveDays = 1
$maxConsecutiveDays = 1

for ($i = 1; $i -lt $sortedActiveDates.Count; $i++) {
    $previousDate = $sortedActiveDates[$i - 1]
    $currentDate = $sortedActiveDates[$i]
    if ($currentDate -eq $previousDate.AddDays(1)) {
        $consecutiveDays++
        if ($consecutiveDays -gt $maxConsecutiveDays) {
            $maxConsecutiveDays = $consecutiveDays
        }
    }
    else {
        $consecutiveDays = 1
    }
}

Write-Verbose "Maximum Consecutive Active Days: $maxConsecutiveDays"

# Calculate Overall Average Operating Time
$totalOperatingDuration = [TimeSpan]::Zero
foreach ($duration in $dayDurations.Values) {
    if ($duration -ne $null) {
        $totalOperatingDuration += $duration
    }
}
if ($dayDurations.Count -gt 0) {
    $averageOperatingDuration = [TimeSpan]::FromTicks([long]($totalOperatingDuration.Ticks / $dayDurations.Count))
} else {
    $averageOperatingDuration = [TimeSpan]::Zero
}
$formattedTotalDuration = "{0:00}:{1:00}" -f $averageOperatingDuration.Hours, $averageOperatingDuration.Minutes

# Dispose of large data structures to free up memory
$sortedActivityTimes = $null
$activeDates = $null
$lockedPeriods = $null

Write-Host "`n--- User's Average Operating Times per Day ---" -ForegroundColor Cyan

foreach ($day in $dayDurations.Keys) {
    $averageDuration = $dayDurations[$day]
    $formattedDuration = "{0:00}:{1:00}" -f $averageDuration.Hours, $averageDuration.Minutes
    $averageStartTime = $dayStartTimes[$day]
    $averageEndTime = $dayEndTimes[$day]
    Write-Host " - ${day}: Average Operating Duration: $formattedDuration hours over $($dayCounts[$day]) day(s)"
    Write-Host "   Average Activity Hours: $averageStartTime - $averageEndTime"
}

Write-Host "`nConclusion:" -ForegroundColor Cyan
Write-Host "Over the analyzed period, the user's average daily active time is approximately $formattedTotalDuration hours (excluding locked periods)." -ForegroundColor Green

Write-Information "`nUBHEX analysis completed."
