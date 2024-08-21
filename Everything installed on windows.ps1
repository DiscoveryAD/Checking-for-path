function Get-InstalledPrograms {

    Write-Host "Fetching installed programs from the registry..." -ForegroundColor Cyan

 

    $installedPrograms = @()

 

    # 32-bit applications on a 64-bit system

    $installedPrograms += Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `

        | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

 

    # 64-bit applications on a 64-bit system or 32-bit applications on a 32-bit system

    $installedPrograms += Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `

        | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

 

    # Installed programs in the current user's context

    $installedPrograms += Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `

        | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

 

    # Filter out entries without a DisplayName

    $installedPrograms = $installedPrograms | Where-Object { $_.DisplayName -ne $null }

 

    return $installedPrograms

}

 

# Function to list all installed updates (patches)

function Get-InstalledUpdates {

    Write-Host "Fetching installed updates (patches) from WMI..." -ForegroundColor Cyan

 

    $installedUpdates = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object Description, HotFixID, InstalledOn

 

    return $installedUpdates

}

 

# Function to list all installed Windows updates (including feature updates)

function Get-WindowsUpdates {

    Write-Host "Fetching installed Windows updates from the Update Session history..." -ForegroundColor Cyan

 

    $updateSession = New-Object -ComObject Microsoft.Update.Session

    $updateSearcher = $updateSession.CreateUpdateSearcher()

    $historyCount = $updateSearcher.GetTotalHistoryCount()

 

    $windowsUpdates = $updateSearcher.QueryHistory(0, $historyCount) | Select-Object Date, Title, Description, ResultCode

 

    return $windowsUpdates

}

 

# Function to list all installed applications via WMI

function Get-InstalledSoftwareViaWMI {

    Write-Host "Fetching installed software from WMI (Win32_Product)..." -ForegroundColor Cyan

 

    $installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate, Vendor

 

    return $installedSoftware

}

 

# Get installed programs

$programs = Get-InstalledPrograms

 

# Get installed updates

$updates = Get-InstalledUpdates

 

# Get Windows updates

$windowsUpdates = Get-WindowsUpdates

 

# Get installed software via WMI

$softwareWMI = Get-InstalledSoftwareViaWMI

 

# Output all installed programs

Write-Host "`nInstalled Programs:" -ForegroundColor Cyan

$programs | Format-Table -AutoSize

 

# Output all installed updates

Write-Host "`nInstalled Updates (Patches):" -ForegroundColor Cyan

$updates | Format-Table -AutoSize

 

# Output all Windows updates

Write-Host "`nWindows Update History:" -ForegroundColor Cyan

$windowsUpdates | Format-Table -AutoSize

 

# Output installed software via WMI

Write-Host "`nInstalled Software (via WMI):" -ForegroundColor Cyan

$softwareWMI | Format-Table -AutoSize