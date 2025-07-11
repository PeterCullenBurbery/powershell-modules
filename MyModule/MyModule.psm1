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