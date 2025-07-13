function Get-IanaTimeZone {
    $win_tz = (Get-TimeZone).Id
    $iana_tz = $null

    # Method 1: .NET TimeZoneInfo API (PowerShell 7.2+ / .NET 6+)
    if ([System.TimeZoneInfo].GetMethod("TryConvertWindowsIdToIanaId", [type[]]@([string],[string].MakeByRefType()))) {
        if ([System.TimeZoneInfo]::TryConvertWindowsIdToIanaId($win_tz, [ref] $iana_tz)) {
            return $iana_tz
        }
    }

    # Method 2: WinRT Calendar API (Windows 10+)
    try {
        return [Windows.Globalization.Calendar,Windows.Globalization,ContentType=WindowsRuntime]::new().GetTimeZone()
    } catch {}

    # Method 3: Parse TimeZoneMapping.xml
    $map_path = Join-Path $Env:WinDir 'Globalization\Time Zone\TimeZoneMapping.xml'
    if (Test-Path $map_path) {
        $map_xml = [xml](Get-Content $map_path)
        $node = $map_xml.TimeZoneMapping.MapTZ | Where-Object { $_.WinID -eq $win_tz -and $_.Default -eq "true" }
        if ($node) {
            return $node.TZID
        }
    }

    # Fallback to Windows ID
    return $win_tz
}

function Get-IsoWeekDate {
    param (
        [datetime]$date = (Get-Date)
    )

    if ([System.Type]::GetType("System.Globalization.ISOWeek")) {
        $iso_week = [System.Globalization.ISOWeek]::GetWeekOfYear($date)
        $iso_year = [System.Globalization.ISOWeek]::GetYear($date)
    } else {
        $iso_day = (([int]$date.DayOfWeek + 6) % 7) + 1
        $weekThursday = $date.AddDays(4 - $iso_day)
        $iso_year = $weekThursday.Year
        $iso_week = [System.Globalization.CultureInfo]::InvariantCulture.Calendar.GetWeekOfYear(
            $weekThursday,
            [System.Globalization.CalendarWeekRule]::FirstFourDayWeek,
            [System.DayOfWeek]::Monday
        )
    }

    $iso_day = (([int]$date.DayOfWeek + 6) % 7) + 1
    return "{0:0000}-W{1:000}-{2:000}" -f $iso_year, $iso_week, $iso_day
}

function Get-IsoOrdinalDate {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [DateTime] $Date = (Get-Date)
    )

    process {
        # Format as YYYY-DDD (year and 3-digit day-of-year)
        $ordinal = "{0:yyyy}-{1:D3}" -f $Date, $Date.DayOfYear
        Write-Output $ordinal
    }
}

function Restart-FileExplorer {
    <#
    .SYNOPSIS
    Restarts Windows File Explorer.

    .DESCRIPTION
    Stops the 'explorer' process and starts it again. This will close and reopen the desktop, taskbar, and any open File Explorer windows.

    .EXAMPLE
    Restart-FileExplorer

    Restarts the File Explorer process.
    #>

    [CmdletBinding()]
    param ()

    try {
        Write-Host "🔄 Stopping Explorer..." -ForegroundColor Yellow
        Stop-Process -Name explorer -Force -ErrorAction Stop
        Start-Sleep -Seconds 1

        Write-Host "🚀 Starting Explorer..." -ForegroundColor Green
        Start-Process explorer.exe
        Write-Host "✅ Explorer restarted successfully." -ForegroundColor Cyan
    }
    catch {
        Write-Host "❌ Failed to restart Explorer: $_" -ForegroundColor Red
    }
}

function Get-PowerShellVersionDetails {
    [OutputType([pscustomobject])]
    param ()

    $results = [ordered]@{}

    $results['PSVersion']         = $PSVersionTable.PSVersion.ToString()
    $results['PSEdition']         = $PSVersionTable.PSEdition
    $results['MajorVersion']      = $PSVersionTable.PSVersion.Major
    $results['ParallelSupported'] = $false
    $results['TernarySupported']  = $false
    $results['NullCoalescing']    = $false
    $results['PipelineChain']     = $false
    $results['PSStyleAvailable']  = $false
    $results['GetErrorAvailable'] = $false

    # 1. ForEach-Object -Parallel (robust test with -join)
    try {
        $output = 1..2 | ForEach-Object -Parallel { $_ * 2 }
        if (($output -join ',') -eq '2,4') {
            $results['ParallelSupported'] = $true
        }
    } catch {}

    # 2. Ternary operator
    try {
        $ternaryTest = Invoke-Expression '[bool]$x = $true; $x ? "yes" : "no"'
        if ($ternaryTest -eq 'yes') {
            $results['TernarySupported'] = $true
        }
    } catch {}

    # 3. Null-coalescing operator
    try {
        $nullCoalesce = Invoke-Expression '$null ?? "fallback"'
        if ($nullCoalesce -eq 'fallback') {
            $results['NullCoalescing'] = $true
        }
    } catch {}

    # 4. Pipeline chain operator (&&)
    try {
        $pipelineTest = Invoke-Expression '1..1 | ForEach-Object { "ok" } && "yes"'
        if ($pipelineTest -match 'yes') {
            $results['PipelineChain'] = $true
        }
    } catch {}

    # 5. $PSStyle
    try {
        if ($null -ne $PSStyle) {
            $results['PSStyleAvailable'] = $true
        }
    } catch {}

    # 6. Get-Error cmdlet
    try {
        if (Get-Command Get-Error -ErrorAction SilentlyContinue) {
            $results['GetErrorAvailable'] = $true
        }
    } catch {}

    # Final conclusion
    $results['Conclusion'] = if (
        $results['PSEdition'] -eq 'Core' -or
        $results['MajorVersion'] -ge 7 -or
        $results['ParallelSupported'] -or
        $results['TernarySupported'] -or
        $results['NullCoalescing'] -or
        $results['PipelineChain'] -or
        $results['PSStyleAvailable'] -or
        $results['GetErrorAvailable']
    ) {
        "✅ PowerShell 7+ (Core)"
    } elseif (
        $results['PSEdition'] -eq 'Desktop' -and
        $results['MajorVersion'] -eq 5
    ) {
        "🖥️ Windows PowerShell 5.1 (Desktop)"
    } else {
        "❓ Unknown or unsupported PowerShell version"
    }

    [pscustomobject]$results
}

function Add-ToPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathToAdd
    )

    Write-Host "🔧 Input path: $PathToAdd"

    try {
        # Step 1: Resolve absolute path
        $absPath = [System.IO.Path]::GetFullPath($PathToAdd)
        if (-not (Test-Path $absPath)) {
            throw "❌ Path does not exist: $absPath"
        }

        # If it's a file, get its parent folder
        if (-not (Get-Item $absPath).PSIsContainer) {
            $absPath = Split-Path $absPath
        }

        $normalized = $absPath.TrimEnd('\')
        Write-Host "📁 Normalized path: $normalized"

        # Step 2: Get PATH from registry (with symbolic variables)
        $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        )
        $rawPath = $reg.GetValue("Path", "", "DoNotExpandEnvironmentNames")
        $reg.Close()

        Write-Host "📍 Current PATH (raw):"
        Write-Host $rawPath

        # Step 3: Process and expand entries
        $entries = $rawPath -split ';'
        $normalizedLower = $normalized.ToLowerInvariant()
        $seen = @{}
        $rebuilt = @($normalized)
        $seen[$normalizedLower] = $true
        $alreadyExists = $false

        Write-Host "🔍 Checking each existing PATH entry against target:"

        foreach ($entry in $entries) {
            $trimmed = $entry.Trim().TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            $expanded = [Environment]::ExpandEnvironmentVariables($trimmed).TrimEnd('\')
            $lowerExpanded = $expanded.ToLowerInvariant()

            # Log only if expansion changed the string
            if ($trimmed -ne $expanded) {
                Write-Host ("   - Original: {0,-70} → Expanded: {1}" -f $trimmed, $expanded)
            }

            # Detect if the normalized path already exists
            if ($lowerExpanded -eq $normalizedLower) {
                $alreadyExists = $true
            }

            # Avoid duplicates
            if (-not $seen.ContainsKey($lowerExpanded)) {
                $rebuilt += $expanded
                $seen[$lowerExpanded] = $true
            }
        }

        if ($alreadyExists) {
            Write-Host "✅ Path already present in system PATH (via expanded match)."
            return
        }

        $newPath = ($rebuilt -join ';')
        Write-Host "🧩 New PATH to set in registry (fully expanded):"
        Write-Host $newPath

        # Step 4: Overwrite registry with new flattened PATH
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name Path -Value $newPath
        Write-Host "✅ Path added to the top of system PATH."

        # Step 5: Broadcast environment change
        $signature = @"
[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        Add-Type -MemberDefinition $signature -Name 'Win32SendMessageTimeout' -Namespace Win32Functions

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [UIntPtr]::Zero

        $r = [Win32Functions.Win32SendMessageTimeout]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [UIntPtr]::Zero,
            "Environment",
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($r -eq [IntPtr]::Zero) {
            Write-Host "⚠️ Environment change broadcast may have failed."
        } else {
            Write-Host "📢 Environment update broadcast sent."
        }

    } catch {
        Write-Error $_
    }
}

function Remove-FromPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathToRemove
    )

    Write-Host "🧹 Input path to remove: $PathToRemove"

    try {
        # Step 1: Resolve absolute path
        $absPath = [System.IO.Path]::GetFullPath($PathToRemove)
        if (-not (Test-Path $absPath)) {
            throw "❌ Path does not exist: $absPath"
        }

        if (-not (Get-Item $absPath).PSIsContainer) {
            $absPath = Split-Path $absPath
        }

        $normalized = $absPath.TrimEnd('\')
        $normalizedLower = $normalized.ToLowerInvariant()
        Write-Host "📁 Normalized path: $normalized"

        # Step 2: Read PATH from registry without expanding env vars
        $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        )
        $rawPath = $reg.GetValue("Path", "", "DoNotExpandEnvironmentNames")
        $reg.Close()

        Write-Host "📍 Current PATH (raw):"
        Write-Host $rawPath

        # Step 3: Split and rebuild entries (without the one we want to remove)
        $entries = $rawPath -split ';'
        $seen = @{}
        $rebuilt = @()
        $removed = $false

        Write-Host "🔍 Checking each PATH entry against target:"

        foreach ($entry in $entries) {
            $trimmed = $entry.Trim().TrimEnd('\')
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            $expanded = [Environment]::ExpandEnvironmentVariables($trimmed).TrimEnd('\')
            $lowerExpanded = $expanded.ToLowerInvariant()

            if ($trimmed -ne $expanded) {
                Write-Host ("   - Original: {0,-70} → Expanded: {1}" -f $trimmed, $expanded)
            }

            if ($lowerExpanded -eq $normalizedLower) {
                Write-Host "❌ Match found. Skipping: $expanded"
                $removed = $true
                continue
            }

            if (-not $seen.ContainsKey($lowerExpanded)) {
                $rebuilt += $expanded
                $seen[$lowerExpanded] = $true
            }
        }

        if (-not $removed) {
            Write-Host "✅ Path not found in system PATH."
            return
        }

        $newPath = ($rebuilt -join ';')
        Write-Host "🧩 New PATH to set in registry (fully expanded):"
        Write-Host $newPath

        # Step 4: Update registry
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name Path -Value $newPath
        Write-Host "✅ Path removed from system PATH."

        # Step 5: Broadcast environment change
        $signature = @"
[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        Add-Type -MemberDefinition $signature -Name 'Win32SendMessageTimeout' -Namespace Win32Functions

        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [UIntPtr]::Zero

        $r = [Win32Functions.Win32SendMessageTimeout]::SendMessageTimeout(
            $HWND_BROADCAST,
            $WM_SETTINGCHANGE,
            [UIntPtr]::Zero,
            "Environment",
            $SMTO_ABORTIFHUNG,
            5000,
            [ref]$result
        )

        if ($r -eq [IntPtr]::Zero) {
            Write-Host "⚠️ Environment change broadcast may have failed."
        } else {
            Write-Host "📢 Environment update broadcast sent."
        }

    } catch {
        Write-Error $_
    }
}

function Get-FileSize {
    <#
    .SYNOPSIS
    Returns the total size in bytes of a file or all files within a directory.

    .DESCRIPTION
    This function accepts a path to either a file or directory.
    If a file, it returns its size.
    If a directory, it recursively computes the sum of all file sizes inside.

    .PARAMETER Path
    The path to the file or directory.

    .EXAMPLE
    Get-FileSize -Path "C:\Users\Administrator\Desktop"

    .OUTPUTS
    [Int64] The total size in bytes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path '$Path' does not exist."
    }

    $item = Get-Item -LiteralPath $Path

    if ($item.PSIsContainer) {
        $size = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum
        return $size.Sum
    } else {
        return $item.Length
    }
}