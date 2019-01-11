<#
.SYNOPSIS
    Remove unnecessary apps and tweaks Windows 10 for the best perfomance/privacy.
.DESCRIPTION
    Decrapify Windows 10
.PARAMETER TempFolders
    Temporary folders to be deleted.
.PARAMETER CertificateLocation
    Shared folder where certificate is stored.
.INPUTS
    None
.OUTPUTS
    None
.EXAMPLE
    Execute manually using powershell after fresh install of Windows 10.  
.NOTES
    Author:             Wan Shahruddin
    Why?:               Setting up a new Windows 10 computer takes so much time. This script's purpose is to shorten and automate a lot of the tasks
                        as well as tweaking some of the computer settings for privacy and performance purpose. 
#>

Params (
    $TempFolders = @("C:\Windows\Temp\*","C:\Users\*\Appdata\Local\Temp\*")
    $CertificateLocation = "UNC File Path eg \\192.168.1.5\SharedFolder\Certificate.pem"
)

############################
# Do not modify below this #
############################

#Elevate Powershell to Administrator
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

#Chocolatey Package Manager#
    #Install Chocolatey
    Set-ExecutionPolicy Bypass; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    #Install Adobe Reader DC
    choco install adobereader -y

    #Install CCleaner
    choco install ccleaner -y

    #Install Google Chrome
    choco install googlechrome -y

    #Install TeamViewer
    choco install teamviewer -y 

#####

#Local Machine Settings#

    #Provisioned Apps
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -notlike "*Store*" -and $_.Name -notlike "*Calculator*" -and $_.Name -notlike "*Windows.Photos*" -and $_.Name -notlike "*SoundRecorder*" -and $_.Name -notlike "*MSPaint*" -and $_.Name -notlike "*StickyNotes*"} | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -notlike "*Store*" -and $_.Name -notlike "*Calculator*" -and $_.Name -notlike "*Windows.Photos*" -and $_.Name -notlike "*SoundRecorder*" -and $_.Name -notlike "*MSPaint*" -and $_.Name -notlike "*StickyNotes*"} | Remove-AppxPackage -ErrorAction SilentlyContinue

    #Scheduled Tasks
    Get-ScheduledTask "SmartScreenSpecific","Microsoft Compatibility Appraiser","Consolidator","KernelCeipTask","UsbCeip","Microsoft-Windows-DiskDiagnosticDataCollector","GatherNetworkInfo","QueueReporting" | Disable-ScheduledTask

    #Services
    Get-Service DiagTrack,DmwApPushService,OneSyncSvc,XblAuthManager,XblGameSave,XboxNetApiSvc,WMPNetworkSvc,BITS,SysMain | Stop-Service -Passthru | Set-Service -StartupType Disabled

    #Application Compatibility
        #Telemetry
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /T Reg_Dword /V "AITEnable" /D 0 /F 

        #Inventory Collector
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /T Reg_Dword /V "DisableInventory" /D 1 /F

        #Steps Recorder
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /T Reg_Dword /V "DisableUAR" /D 1 /F

    #Cloud Content
        #Tips
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /T Reg_Dword /V "DisableSoftLanding" /D 1 /F

        #Consumer Experience Features
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /T Reg_Dword /V "DisableWindowsConsumerFeatures" /D 1 /F

    #Data Collection
        #Basic Telemetry
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /T Reg_Dword /V "AllowTelemetry" /D 0 /F

        #Feedbacks
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /T Reg_Dword /V "DoNotShowFeedbackNotification" /D 1 /F

    #Preview Builds
        #Pre Release Features
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /T Reg_Dword /V "EnableConfigFlighting" /D 0 /F

    #Delivery Optimization
        #Delivery Optimizatio Over LAN Only
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /T Reg_Dword /V "DODownloadmode" /D 1 /F 

    #Location & Sensors
        #Location
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /T Reg_Dword /V "DisableLocation" /D 1 /F

        #Sensors
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /T Reg_Dword /V "DisableSensors" /D 1 /F

    #Edge
        #Tracking
        Reg Add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /T Reg_Dword /V "DoNotTrack" /D 1 /F

    #OneDrive
        #File Storage
        Reg Add "HKLM\Software\Policies\Microsoft\OneDrive" /T Reg_Dword /V "DisableFileSyncNGSC" /D 1 /F
        Reg Add "HKLM\Software\Policies\Microsoft\OneDrive" /T Reg_Dword /V "DisableFileSync" /D 1 /F

    #Search
        #Cortana
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /T Reg_Dword /V "AllowCortana" /D 0 /F

        #Cortana On Lock Screen
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /T Reg_Dword /V "AllowCortanaAboveLock" /D 0 /F

        #Desktop Web Search
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /T Reg_Dword /V "DisableWebSearch" /D 1 /F

        #Web Results In Search
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /T Reg_Dword /V "ConnectedSearchUseWeb" /D 0 /F

    #Sync
        #Sync Anything
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /T Reg_Dword /V "DisableSettingSync" /D 2 /F

        #Changes To Sync
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /T Reg_Dword /V "DisableSettingSyncUserOverride" /D 1 /F

    #Windows Update
        #Featured Software Notification
        Reg Add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /T Reg_Dword /V "EnableFeaturedSoftware" /D 0 /F

    #MetaData Collection & Advertising Info
        #Advertising Info
        Reg Add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /T Reg_Dword /V "Enabled" /D 0 /F

        #Meta Data Collection
        Reg Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /T Reg_Dword /V "PreventDeviceMetadataFromNetwork" /D 1 /F

    #Apps From Other Device
    Reg Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /T Reg_Dword /V "UserAuthPolicy" /D 2 /F

    #Sign In Info
    Reg Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /T Reg_Dword /V "ARSOUserConsent" /D 2 /F

    #Malicious Software Removal Tool
        #Windows Update
        Reg Add "HKLM\Software\Policies\Microsoft\MRT" /T Reg_Dword /V "DontOfferThroughgWUAU" /D 1 /F

        #Consumer Experience Improvement Program
        Reg Add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /T Reg_Dword /V "CEIPEnable" /D 0 /F
    
    #Remote User Access Control
    Reg Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /T Reg_Dword /V "LocalAccountTokenFilterPolicy" /D 1 /F
    
    #Start Tiles
    $startlayoutstr = @"
    <LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
        <DefaultLayoutOverride>
            <StartLayoutCollection>
              <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
                <start:Group Name="Group Name" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
                  <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
                </start:Group>        
              </defaultlayout:StartLayout>
            </StartLayoutCollection>
        </DefaultLayoutOverride>
    </LayoutModificationTemplate>
"@
    Add-Content $Env:TEMP\startlayout.xml $startlayoutstr
    Import-StartLayout -layoutpath $Env:TEMP\startlayout.xml -mountpath $Env:SYSTEMDRIVE\
    Remove-Item $Env:TEMP\startlayout.xml

    #Network
        #Set Network Connection To Private (Ethernet)
        Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private

    #Firewall
        #Spiceworks
        netsh advfirewall firewall add rule name="TCP Spiceworks" dir=in action=allow protocol=TCP localport=9675-9676
        netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes
        netsh advfirewall firewall set rule group="Remote Service Management" new enable=yes
        
        #PDQ Deploy
        netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes

    #Powershell Remoting
    Enable-PSRemoting

    #Certificate Authorities
        #Sophos XG210
        Import-Certificate -FilePath "$CertificateLocation" -CertStoreLocation "Cert:\LocalMachine\Root"

    #Temp Files
        #Delete Temp Files
        Remove-Item $TempFolders -force -recurse

        #Change Temp Directory
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" -Name Temp "C:\Temp"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP "C:\Temp"
    
    #Rename Computer
    Write-Host "Enter New PC Name (Example-1-2)"
    $computerName = Read-Host
    Rename-Computer -NewName $computerName

    Read-Host "Press enter key to exit..."
    exit