$ErrorActionPreference = 'SilentlyContinue'

#Unnecessary Windows 10 AppX apps that will be removed by the blacklist.
$global:Bloatware = @(
    "Microsoft.PPIProjection"
    "Microsoft.BingNews"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"                                    # Issue 77
    "Microsoft.Office.Lens"                             # Issue 77
    "Microsoft.Office.OneNote"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.RemoteDesktop"                           # Issue 120
    "Microsoft.SkypeApp"
    "Microsoft.StorePurchaseApp"
    "Microsoft.Office.Todo.List"                        # Issue 77
    "Microsoft.Whiteboard"                              # Issue 77
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"

    #Sponsored Windows 10 AppX Apps
    #Add sponsored/featured apps to remove in the "*AppName*" format
    "EclipseManager"
    "ActiproSoftwareLLC"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "Duolingo-LearnLanguagesforFree"
    "PandoraMediaInc"
    "CandyCrush"
    "BubbleWitch3Saga"
    "Wunderlist"
    "Flipboard"
    "Twitter"
    "Facebook"
    "Spotify"                                           # Issue 123
    "Minecraft"
    "Royal Revolt"
    "Sway"                                              # Issue 77
    "Dolby"                                             # Issue 78

    #Optional: Typically not removed but you can if you need to for some reason
    #"Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe"
    #"Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe"
    "Microsoft.BingWeather"
)

$global:WhiteListedApps = @(
    "Microsoft.WindowsCalculator"               # Microsoft removed legacy calculator
    "Microsoft.WindowsStore"                    # Issue 1
    "Microsoft.Windows.Photos"                  # Microsoft disabled/hid legacy photo viewer
    "CanonicalGroupLimited.UbuntuonWindows"     # Issue 10
    # "Microsoft.Xbox.TCUI"                       # Issue 25, 91  Many home users want to play games
    # "Microsoft.XboxApp"
    # "Microsoft.XboxGameOverlay"
    # "Microsoft.XboxGamingOverlay"               # Issue 25, 91  Many home users want to play games
    # "Microsoft.XboxIdentityProvider"            # Issue 25, 91  Many home users want to play games
    # "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MicrosoftStickyNotes"            # Issue 33  New functionality.
    "Microsoft.MSPaint"                         # Issue 32  This is Paint3D, legacy paint still exists in Windows 10
    "Microsoft.WindowsCamera"                   # Issue 65  New functionality.
    "\.NET"
    "Microsoft.HEIFImageExtension"              # Issue 68
    "Microsoft.ScreenSketch"                    # Issue 55: Looks like Microsoft will be axing snipping tool and using Snip & Sketch going forward
    "Microsoft.StorePurchaseApp"                # Issue 68
    "Microsoft.VP9VideoExtensions"              # Issue 68
    "Microsoft.WebMediaExtensions"              # Issue 68
    "Microsoft.WebpImageExtension"              # Issue 68
    "Microsoft.DesktopAppInstaller"             # Issue 68
    "WindSynthBerry"                            # Issue 68
    "MIDIBerry"                                 # Issue 68
    "Slack"                                     # Issue 83
    "*Nvidia*"                                  # Issue 198
    "Microsoft.MixedReality.Portal"             # Issue 195
)

#convert to regular expression to allow for the super-useful -match operator
$global:BloatwareRegex = $global:Bloatware -join '|'
$global:WhiteListedAppsRegex = $global:WhiteListedApps -join '|'

function main_form {

    function Remove_app_native {
        $ErrorActionPreference = 'SilentlyContinue'
        Function Sysprep {

            # Disable Windows Store Automatic Updates
            $lb_log.text = 'Desabilitando atualização automatica da Windows Store...'
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
            If (!(Test-Path $registryPath)) {
                Mkdir $registryPath
                New-ItemProperty $registryPath AutoDownload -Value 2 
            }
            Set-ItemProperty $registryPath AutoDownload -Value 2

            #Stop WindowsStore Installer Service and set to Disabled
            $lb_log.text = 'Parando Serviço de instalação...'
            Stop-Service InstallService

            $lb_log.text = 'Configurando inicio do Serviço de instalação para desabilitado...'
            Set-Service InstallService -StartupType Disabled
        }

        $lb_log.text = 'Checando DMW Serviço...'
        Function CheckDMWService {

            Param([switch]$Debloat)

            If (Get-Service dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
                Set-Service dmwappushservice -StartupType Automatic
            }

            If (Get-Service dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
                Start-Service dmwappushservice
            } 
        }

        Function DebloatAll {
            $lb_log.text = 'Removendo aplicativos nativos...'
            #Removes AppxPackages
            Get-AppxPackage | Where-Object { !($_.Name -cmatch $global:WhiteListedAppsRegex) -and !($NonRemovables -cmatch $_.Name) } | Remove-AppxPackage
            Get-AppxProvisionedPackage -Online | Where-Object { !($_.DisplayName -cmatch $global:WhiteListedAppsRegex) -and !($NonRemovables -cmatch $_.DisplayName) } | Remove-AppxProvisionedPackage -Online
            Get-AppxPackage -AllUsers | Where-Object { !($_.Name -cmatch $global:WhiteListedAppsRegex) -and !($NonRemovables -cmatch $_.Name) } | Remove-AppxPackage
            $lb_log.text = 'Aplicativos nativos removidos...'
        }

        #Creates a PSDrive to be able to access the 'HKCR' tree
        $lb_log.text = 'Criando PSDrive para acessar o registro ROOT...'
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

        $lb_log.text = 'Criando chaves de remoção de registro...'
        Function Remove-Keys {         
            #These are the registry keys that it will delete.
            $Keys = @(
      
                #Remove Background Tasks
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
      
                #Windows File
                "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
      
                #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
      
                #Scheduled Tasks to delete
                "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
      
                #Windows Protocol Keys
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
         
                #Windows Share Target
                "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            )
  
            #This writes the output of each key it is removing and also removes the keys listed above.
            ForEach ($Key in $Keys) {
                $lb_log.text = "Removing $Key from registry"
                Remove-Item $Key -Recurse
            }
        }

        Function Protect-Privacy { 
            
            #Creates a PSDrive to be able to access the 'HKCR' tree
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

            $lb_log.text = 'Desabilitando Windows Feedback Experience...'
            #Disables Windows Feedback Experience
            $Advertising = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            If (Test-Path $Advertising) {
                Set-ItemProperty $Advertising Enabled -Value 0
            }
      
            #Stops Cortana from being used as part of your Windows Search Function
            $lb_log.text = 'Desabilitando cortana das pesquisas...'
            $Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            If (Test-Path $Search) {
                Set-ItemProperty $Search AllowCortana -Value 0
            }
      
            #Stops the Windows Feedback Experience from sending anonymous data
            $lb_log.text = 'Desativando o Windows feedback experience de enviar dados anonymous...'
            $Period1 = 'HKCU:\Software\Microsoft\Siuf'
            $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
            $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
            If (!(Test-Path $Period3)) { 
                mkdir $Period1
                mkdir $Period2
                mkdir $Period3
                New-ItemProperty $Period3 PeriodInNanoSeconds -Value 0
            }
             
            #Prevents bloatware applications from returning
            $lb_log.text = 'Adicionando chave do registro para prevenir a volta dos apps removidos...'
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            If (!(Test-Path $registryPath)) {
                Mkdir $registryPath
                New-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 
            }          
  
            $lb_log.text = 'Permitindo remoção do Mixed Reality Portal...'
            $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
            If (Test-Path $Holo) {
                Set-ItemProperty $Holo FirstRunSucceeded -Value 0
            }
  
            #Disables live tiles
            $lb_log.text = 'Desabilitando Live tiles...'
            $Live = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
            If (!(Test-Path $Live)) {
                mkdir $Live  
                New-ItemProperty $Live NoTileApplicationNotification -Value 1
            }
  
            #Turns off Data Collection via the AllowTelemtry key by changing it to 0
            $lb_log.text = 'Desativando coleçã de dados via telemetria...'
            $DataCollection = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
            If (Test-Path $DataCollection) {
                Set-ItemProperty $DataCollection AllowTelemetry -Value 0
            }
  
            #Disables People icon on Taskbar
            $lb_log.text = 'Desabilitando Icones de pessoas na barra de tarefas...'
            $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
            If (Test-Path $People) {
                Set-ItemProperty $People PeopleBand -Value 0
            }

            #Disables suggestions on start menu
            $lb_log.text = 'Desabilitando sugestões no menu inicial...'
            $Suggestions = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    
            If (Test-Path $Suggestions) {
                Set-ItemProperty $Suggestions SystemPaneSuggestionsEnabled -Value 0
            }
        
            # Desabilitando pesquisa do Bing via menu de inicio
            $lb_log.text = 'Desabilitando pesquisa do Bing via menu de inicio...'
            $BingSearch = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            If (Test-Path $BingSearch) {
                Set-ItemProperty $BingSearch DisableSearchBoxSuggestions -Value 1
            }
        
            $lb_log.text = 'Removendo CloudStore...'
            $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
            If (Test-Path $CloudStore) {
                Stop-Process Explorer.exe -Force
                Remove-Item $CloudStore -Recurse -Force
                Start-Process Explorer.exe -Wait
            }

            #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
            reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
            Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
            Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
            Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
            reg unload HKU\Default_User
  
            $lb_log.text = 'Desabilitando tarefas que são desnecessárias...'
            #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask
            Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask
            Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask
            Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask
            Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask
            Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask
        }

        Function UnpinStart {
            # https://superuser.com/a/1442733
            # Requires -RunAsAdministrator

            $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
<DefaultLayoutOverride>
    <StartLayoutCollection>
        <defaultlayout:StartLayout GroupCellWidth="6" />
    </StartLayoutCollection>
</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

            $layoutFile = "C:\Windows\StartMenuLayout.xml"

            #Delete layout file if it already exists
            If (Test-Path $layoutFile) {
                Remove-Item $layoutFile
            }

            #Creates the blank layout file
            $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

            $regAliases = @("HKLM", "HKCU")

            #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
            foreach ($regAlias in $regAliases) {
                $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
                $keyPath = $basePath + "\Explorer" 
                IF (!(Test-Path -Path $keyPath)) { 
                    New-Item -Path $basePath -Name "Explorer"
                }
                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
                Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
            }

            #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
            Stop-Process -name explorer
            Start-Sleep -s 5
            $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
            Start-Sleep -s 5

            #Enable the ability to pin items again by disabling "LockedStartLayout"
            foreach ($regAlias in $regAliases) {
                $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
                $keyPath = $basePath + "\Explorer" 
                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
            }

            #Restart Explorer and delete the layout file
            Stop-Process -name explorer

            # Uncomment the next line to make clean start menu default for all new users
            Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

            Remove-Item $layoutFile
        }
    
        Function CheckInstallService {

            If (Get-Service InstallService | Where-Object { $_.Status -eq "Stopped" }) {  
                Start-Service InstallService
                Set-Service InstallService -StartupType Automatic 
            }
        }

        $lb_log.text = 'Iniciando preparação do sistema...'
        Sysprep

        $lb_log.text = 'Removendo apps desnecessários...'
        DebloatAll

        $lb_log.text = 'Removendo chaves de registro...'
        Remove-Keys

        Protect-Privacy
        UnpinStart
        CheckDMWService
        CheckInstallService
        $lb_log.text = 'Apps nativos desinstalados...'
    }
    
    #Ativando desempenho maximo
    function Max_perfomance {
        $lb_log.text = 'Coletando esquemas de energia...'
        $powerscheme = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power
        
        $lb_log.text = 'Removendo esquemas de desempenho máximo duplicados...'
        for ($i = 0; $i -lt $powerscheme.Count; $i++) {
            if ($powerscheme[$i].ElementName -eq "Desempenho Máximo") {
                powercfg /delete $powerscheme[$i].InstanceID.Substring("21", $powerscheme[$i].InstanceID.Length - 22)
            }
        }
        $lb_log.text = 'Criando de desempenho máximo...'
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null

        $lb_log.text = 'Coletando novas informações...'
        $powerscheme = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power

        $lb_log.text = 'Ativando desempenho máximo...'
        for ($i = 0; $i -lt $powerscheme.Count; $i++) {
            if ($powerscheme[$i].ElementName -eq "Desempenho Máximo") {
                powercfg /SETACTIVE $powerscheme[$i].InstanceID.Substring("21", $powerscheme[$i].InstanceID.Length - 22)
            }
        }

        $planned = @(
            "monitor-timeout-ac"
            "monitor-timeout-dc"
            "disk-timeout-ac"
            "disk-timeout-dc"
            "standby-timeout-ac"
            "standby-timeout-dc"
            "hibernate-timeout-ac"
            "hibernate-timeout-dc"
        )

        foreach ($plan in $planned) {
            $lb_log.text = "Alterando " + $plan + " para desativado"
            powercfg /change $plan 0
        }

        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Value 3
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name UserPreferencesMask -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x12, 0x00, 0x00, 0x00))
        }
        catch {}

        $lb_log.text = 'Modo desempenho ativado...'
        Remove-Item -force Null
    }
    
    #Desativando Modo Hibernação
    function Not_hibernate {  

        $lb_log.text = 'Desativando Hibernação...'

        powercfg.exe /hibernate off | Out-Null
        Remove-Item -force Null

        $lb_log.text = 'Hibernação Desativada...'

    }
    
    function Visualizer_photos {
        $lb_log.text = 'Adicionando visualizador de fotos do windows...'

        REG ADD "HKCU\SOFTWARE\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f | Out-Null

        $lb_log.text = 'Visualizador de fotos do windows Adicionado...'
    }

    function Remove_onedrive {
        If (Test-Path "$env:USERPROFILE\OneDrive\*") {
            $lb_log.text = 'Arquivos do oneDrive encontrados...'
            Start-Sleep 1
          
            If (Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles") {
                $lb_log.text = 'Arquivos de backup do oneDrive encontrados...'
            }
            else {
                If (!(Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles")) {
                    $lb_log.text = 'Criando Backup do oneDrive...'
                    New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
                    $lb_log.text = "Successfully created the folder 'OneDriveBackupFiles' on your desktop."
                    $lb_log.text = 'Pasta OneDriveBackupFiles criada com sucesso...'
                }
            }
            Start-Sleep 1
            Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
            $lb_log.text = 'Movendo arquivos do oneDrive para OneDriveBackupFiles...'
            Start-Sleep 1
            $lb_log.text = 'Processando para remover oneDrive...'
            Start-Sleep 1
        }
        Else {
            $lb_log.text = "Either the OneDrive folder does not exist or there are no files to be found in the folder. Proceeding with removal of OneDrive."
            Start-Sleep 1
            $lb_log.text = "Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'."
            $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
            If (!(Test-Path $OneDriveKey)) {
                Mkdir $OneDriveKey
                Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
            }
            Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
        }

        $lb_log.text = "Uninstalling OneDrive. Please wait..."

        New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Stop-Process -Name "OneDrive*"
        Start-Sleep 2
        If (!(Test-Path $onedrive)) {
            $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        }
        Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
        Start-Sleep 2
        $lb_log.text = "Stopping explorer"
        Start-Sleep 1
        taskkill.exe /F /IM explorer.exe
        Start-Sleep 3
        $lb_log.text = "Removing leftover files"
        If (Test-Path "$env:USERPROFILE\OneDrive") {
            Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
        }
        If (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") {
            Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
        }
        If (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") {
            Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
        }
        If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
            Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
        }
        $lb_log.text = "Removing OneDrive from windows explorer"
        If (!(Test-Path $ExplorerReg1)) {
            New-Item $ExplorerReg1
        }
        Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
        If (!(Test-Path $ExplorerReg2)) {
            New-Item $ExplorerReg2
        }
        Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
        $lb_log.text = "Restarting Explorer that was shut down before."
        Start-Process explorer.exe -NoNewWindow
        $lb_log.text = "OneDrive has been successfully uninstalled!"
    
        Remove-item env:OneDrive
    }

    function Disable_telemetry {

        $ErrorActionPreference = 'SilentlyContinue'
        #Disables Windows Feedback Experience
        $lb_log.text = "Disabling Windows Feedback Experience program..."
        $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        If (Test-Path $Advertising) {
            Set-ItemProperty $Advertising Enabled -Value 0 
        }
            
        #Stops Cortana from being used as part of your Windows Search Function
        $lb_log.text = "Stopping Cortana from being used as part of your Windows Search Function"
        $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        If (Test-Path $Search) {
            Set-ItemProperty $Search AllowCortana -Value 0 
        }

        #Disables Web Search in Start Menu
        $lb_log.text = "Disabling Bing Search in Start Menu"
        $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
        If (!(Test-Path $WebSearch)) {
            New-Item $WebSearch
        }
        Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
            
        #Stops the Windows Feedback Experience from sending anonymous data
        $lb_log.text = "Stopping the Windows Feedback Experience program"
        $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
        If (!(Test-Path $Period)) { 
            New-Item $Period
        }
        Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

        #Prevents bloatware applications from returning and removes Start Menu suggestions               
        $lb_log.text = "Adding Registry key to prevent bloatware apps from returning"
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        If (!(Test-Path $registryPath)) { 
            New-Item $registryPath
        }
        Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

        If (!(Test-Path $registryOEM)) {
            New-Item $registryOEM
        }
        Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0 
        Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0 
        Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0          
    
        #Preping mixed Reality Portal for removal    
        $lb_log.text = "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
        $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
        }

        #Disables Wi-fi Sense
        $lb_log.text = "Disabling Wi-Fi Sense"
        $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
        $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
        $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        If (!(Test-Path $WifiSense1)) {
            New-Item $WifiSense1
        }
        Set-ItemProperty $WifiSense1  Value -Value 0 
        If (!(Test-Path $WifiSense2)) {
            New-Item $WifiSense2
        }
        Set-ItemProperty $WifiSense2  Value -Value 0 
        Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
        
        #Disables live tiles
        $lb_log.text = "Disabling live tiles"
        $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
        If (!(Test-Path $Live)) {      
            New-Item $Live
        }
        Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
        
        #Turns off Data Collection via the AllowTelemtry key by changing it to 0
        $lb_log.text = "Turning off Data Collection"
        $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
        If (Test-Path $DataCollection1) {
            Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
        }
        If (Test-Path $DataCollection2) {
            Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
        }
        If (Test-Path $DataCollection3) {
            Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
        }
    
        #Disabling Location Tracking
        $lb_log.text = "Disabling Location Tracking"
        $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        If (!(Test-Path $SensorState)) {
            New-Item $SensorState
        }
        Set-ItemProperty $SensorState SensorPermissionState -Value 0 
        If (!(Test-Path $LocationConfig)) {
            New-Item $LocationConfig
        }
        Set-ItemProperty $LocationConfig Status -Value 0 
        
        #Disables People icon on Taskbar
        $lb_log.text = "Disabling People icon on Taskbar"
        $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0
        } 
        
        #Disables scheduled tasks that are considered unnecessary 
        $lb_log.text = "Disabling scheduled tasks"
        #Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask
        Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask
        Get-ScheduledTask Consolidator | Disable-ScheduledTask
        Get-ScheduledTask UsbCeip | Disable-ScheduledTask
        Get-ScheduledTask DmClient | Disable-ScheduledTask
        Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask

        #$lb_log.text = "Uninstalling Telemetry Windows Updates"
        #Uninstalls Some Windows Updates considered to be Telemetry. !WIP!
        #Wusa /Uninstall /KB:3022345 /norestart /quiet
        #Wusa /Uninstall /KB:3068708 /norestart /quiet
        #Wusa /Uninstall /KB:3075249 /norestart /quiet
        #Wusa /Uninstall /KB:3080149 /norestart /quiet        

        $lb_log.text = "Stopping and disabling WAP Push Service"
        #Stop and disable WAP Push Service
        Stop-Service "dmwappushservice"
        Set-Service "dmwappushservice" -StartupType Disabled

        $lb_log.text = "Stopping and disabling Diagnostics Tracking Service"
        #Disabling the Diagnostics Tracking Service
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled
        $lb_log.text = "Telemetry has been disabled!"
        
    }

    function Disable_cortana {
        $ErrorActionPreference = 'SilentlyContinue'
        $lb_log.text = "Disabling Cortana..."
        $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 0
        $lb_log.text = "Cortana has been disabled..."
    }

    #Limpando
    function Remove_trash {
        $lb_log.text = "Limpando pastas temporarias..."
        
        Remove-Item C:\\Temp\* -force -recurse 2> Null
        Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files" -force -recurse 2> Null
        Remove-Item $env:TEMP\* -force -recurse 2> Null
        Remove-Item $env:windir\Temp\* -recurse -force 2> Null
        Remove-Item $env:windir\Prefetch\* -recurse -force 2> Null
        Remove-Item $env:windir\SoftwareDistribution\Download\* -recurse -force 2> Null
        Remove-Item $env:windir\SystemTemp\* -recurse -force 2> Null
        
        $lb_log.text = "Utilizando limpador do windows..."
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' | ForEach-Object {
            New-ItemProperty -Path $_.PSPath -Name StateFlags0001 -Value 2 -PropertyType DWord -Force 2> Null
        } 2> Null; 
        Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -PassThru 2> Null

        Remove-Item -force Null
    }
    
    #Fazendo Mudanças no registro do computador 
    function Change_register {
        $lb_log.text = "Realizando as alterações no registro do computador"
        #Alterando inicialização do NDU
        REG ADD HKLM\SYSTEM\ControlSet001\Services\Ndu /v start /t REG_DWORD /d 4 /f | Out-Null
         
        #Alterando inicialização dp DOSVC
        REG ADD HKLM\SYSTEM\CurrentControlSet\Services\DoSvc /v Start /t REG_DWORD /d 4 /f | Out-Null
    
        # Alterando inicialização do task schedule 
        REG ADD HKLM\SYSTEM\SYSTEM\CurrentControlSet\Services\Schedule /V start /T REG_DWORD /D 2 /F | Out-Null
    
        #Alterando inicialização dp TimeBrokerSvc
        REG ADD HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc /V start /T REG_DWORD /D 2 /F | Out-Null
    
        # Desativando Aplicações em Segundo plano 
        REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
    
        #Acelerando desligamento 
        REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f | Out-Null
    
        #Escodendo caixa de pesquisa do windows
        #0 = hide completely, 1 = show only icon, 2 = show long search box
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando OneDrive na Inicialização    
        REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /F 2> Null
    
        #Desativando Windows Error Reporting
        schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable | Out-Null
      
        #Desativando Otimização de Entrega
        REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 3 /f | Out-Null
        REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando Modo Hotspot
        REG ADD "HKLM\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v OsuRegistrationStatus /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando Historico de Arquivos
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando Dicas do Windows
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando Ajuda Ativa
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando Logs
        REG ADD "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando FeedBack do Windows
        REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando FeedBack de Ajuda do Windows 
        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando FeedBack de Escrita
        REG ADD "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando Programas do Windows Insider
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando Telemetria do Office 
        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando Estatisticas do Windows Media Player
        REG ADD "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f | Out-Null
    
        #Removendo 3D Builder do menu de Contexto
        REG DELETE "HKEY_CLASSES_ROOT\SystemFileAssociations\.bmp\Shell\T3D Print" /f 2> Null
        REG DELETE "HKEY_CLASSES_ROOT\SystemFileAssociations\.png\Shell\T3D Print" /f 2> Null
        REG DELETE "HKEY_CLASSES_ROOT\SystemFileAssociations\.jpg\Shell\T3D Print" /f 2> Null
    
        #Ativando Meu Computador em vez do Acesso Rapido
        #1 = Meu Computador | 2 = Acesso Rapido
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando Arquivos usados Recentemente no Acesso Rapido
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando Pastas usadas com frequencia no Acesos Rapido
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativando ID de Anuncio
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f | Out-Null
    
        #Desativando Mostrar conteudo Sugerido e APPS Pré Instalados
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /T REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RemediationRequired /T REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f | Out-Null
    
        #Desativa Localização do Windows
        REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f | Out-Null
    
        #Melhorando Performance do Explorer
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f | Out-Null
    
        #Configurando Explorer
        REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f | Out-Null
        REG ADD "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ServerAdminUI /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DontPrettyPath /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v MapNetDrvBtn /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTypeOverlay /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowStatusBar /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 1 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v  PeopleBand /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarGlomLevel /t REG_DWORD /d 0 /f | Out-Null
        REG ADD "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f | Out-Null
    
        function remove_keys {
            $ErrorActionPreference = 'SilentlyContinue'
            $Keys = @(
                
                New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                #Remove Background Tasks
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                
                #Windows File
                "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                
                #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                
                #Scheduled Tasks to delete
                "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                
                #Windows Protocol Keys
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                   
                #Windows Share Target
                "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            )
            
            #This writes the output of each key it is removing and also removes the keys listed above.
            ForEach ($Key in $Keys) {
                $lb_log.text = "Removing $Key from registry"
                Remove-Item $Key -Recurse
            }
            $lb_log.text = "Additional apps keys have been removed!"
        }

        REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ctfmon /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f | Out-Null
        $lb_log.text = ("Registro Modificado...")
        
        remove_keys
        Remove-Item -force Null
    }
    
    #Desativando Serviços e apps de Inicialização
    function Disable_start_services {
        $lb_log.text = "Desabilitando Serviços de Inicialização..."
    
        #Desativando SysMain
        sc config SysMain start= disabled | Out-Null
    
        #Desativando WSearch
        # sc config WSearch start= disabled | Out-Null
        sc config MicrosoftEdgeElevationService start= disabled | Out-Null
        sc config edgeupdate start= disabled | Out-Null
        sc config edgeupdatem start= disabled | Out-Null
        sc config GoogleChromeElevationService start= disabled | Out-Null
        sc config gupdate start= disabled | Out-Null
        sc config gupdatem start= disabled | Out-Null
        sc config XboxGipSvc start= disabled | Out-Null
    
        #Desabilitando WinSAT do agendador de tarefas
        schtasks /change /TN '\Microsoft\Windows\Maintenance\WinSAT' /disable | Out-Null
    
        Remove-Item -force Null
        $lb_log.text = "Serviços desativados na inicialização..."
    
    }

    function Form {
      
        Add-Type -AssemblyName System.Windows.Forms
        $timer_Dism = New-Object System.Windows.Forms.timer
        $timer_sfc = New-Object System.Windows.Forms.timer
        [System.Windows.Forms.Application]::EnableVisualStyles()
    
        $suporte_GUI = New-Object system.Windows.Forms.Form
        $suporte_GUI.ClientSize = New-Object System.Drawing.Point(600, 400)
        $suporte_GUI.text = "Limpeza e Suporte"
        $suporte_GUI.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#343434")
        $suporte_GUI.FormBorderStyle = 'Fixed3D'
        $suporte_GUI.Icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command powershell).Path)
        $suporte_GUI.StartPosition = "CenterScreen"
        $suporte_GUI.Opacity = .98
        $suporte_GUI.MaximizeBox = $false
        
        function container_titleapp {

            $lb_container_title_top = New-Object System.Windows.Forms.Label
            $lb_container_title_top.Location = New-Object System.Drawing.Point(33, -1)
            $lb_container_title_top.Size = New-Object System.Drawing.Size(226, 56.5)
            $lb_container_title_top.BorderStyle = "None"
            $lb_container_title_top.add_paint({ $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
    
            $lb_title_top = New-Object System.Windows.Forms.Label
            $lb_title_top.Location = New-Object System.Drawing.Point(41, 5)
            $lb_title_top.Size = New-Object System.Drawing.Size(210, 45)
            $lb_title_top.Text = "FERRAMENTA DE SUPORTE DO WINDOWS"
            $lb_title_top.TextAlign = "MiddleCenter"
            $lb_title_top.BorderStyle = "None"
            $lb_title_top.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
            $lb_title_top.Font = New-Object System.Drawing.Font('Inter', 12, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

            $suporte_GUI.controls.AddRange(@(   
                    $lb_title_top,
                    $lb_container_title_top
                ))


        }

        function container_namecomputer {
            $lb_container_namecomputer = New-Object System.Windows.Forms.Label
            $lb_container_namecomputer.Location = New-Object System.Drawing.Point(24, 69)
            $lb_container_namecomputer.Size = New-Object System.Drawing.Size(243, 60)
            $lb_container_namecomputer.BorderStyle = "None"
            $lb_container_namecomputer.add_paint({ $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
            
            $line_computername = New-Object System.Windows.Forms.Label
            $line_computername.Location = New-Object System.Drawing.Point(30, 90)
            $line_computername.Size = New-Object System.Drawing.Size(230, 1)
            $line_computername.BorderStyle = "None"
            $line_computername.add_paint({
                    $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 1)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
    
            $lb_title_computername = New-Object System.Windows.Forms.Label
            $lb_title_computername.Location = New-Object System.Drawing.Point(30, 74)
            $lb_title_computername.Size = New-Object System.Drawing.Size(231, 14)
            $lb_title_computername.Text = 'NOME DO COMPUTADOR'
            $lb_title_computername.Font = New-Object System.Drawing.Font('Inter', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
            $lb_title_computername.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
            $lb_title_computername.TextAlign = 'MiddleCenter'
    
            $lb_computername = New-Object System.Windows.Forms.Label
            $lb_computername.Location = New-Object System.Drawing.Point(30, 95)
            $lb_computername.Size = New-Object System.Drawing.Size(230, 30)
            $lb_computername.Text = $env:computername
            $lb_computername.Font = New-Object System.Drawing.Font('Inter', 15, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
            $lb_computername.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
            $lb_computername.TextAlign = 'MiddleCenter'


            $suporte_GUI.controls.AddRange(@(   
                    $lb_computername,
                    $lb_title_computername,
                    $line_computername,
                    $lb_container_namecomputer    
                ))

        }

        function container_ipcomputer {

            $ipcomputer = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=$true | Select-Object -ExpandProperty IPAddress
            

            $lb_container_ipcomputer = New-Object System.Windows.Forms.Label
            $lb_container_ipcomputer.Location = New-Object System.Drawing.Point(24, 140)
            $lb_container_ipcomputer.Size = New-Object System.Drawing.Size(243, 60)
            $lb_container_ipcomputer.BorderStyle = "None"
            $lb_container_ipcomputer.add_paint({ $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
            
            $line_computerip = New-Object System.Windows.Forms.Label
            $line_computerip.Location = New-Object System.Drawing.Point(30, 161)
            $line_computerip.Size = New-Object System.Drawing.Size(230, 1)
            $line_computerip.BorderStyle = "None"
            $line_computerip.add_paint({
                    $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 1)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
    
            $lb_title_computerip = New-Object System.Windows.Forms.Label
            $lb_title_computerip.Location = New-Object System.Drawing.Point(30, 145)
            $lb_title_computerip.Size = New-Object System.Drawing.Size(231, 14)
            $lb_title_computerip.Text = 'IP DO COMPUTADOR'
            $lb_title_computerip.Font = New-Object System.Drawing.Font('Inter', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
            $lb_title_computerip.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
            $lb_title_computerip.TextAlign = 'MiddleCenter'
    
            $lb_computerip = New-Object System.Windows.Forms.Label
            $lb_computerip.Location = New-Object System.Drawing.Point(30, 166)
            $lb_computerip.Size = New-Object System.Drawing.Size(230, 30)
            $lb_computerip.Text = $ipcomputer[0]
            $lb_computerip.Font = New-Object System.Drawing.Font('Inter', 15, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
            $lb_computerip.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
            $lb_computerip.TextAlign = 'MiddleCenter'

            $suporte_GUI.controls.AddRange(@(   
                    $lb_computerip,
                    $lb_title_computerip,
                    $line_computerip,
                    $lb_container_ipcomputer    
                ))

        }

        # Lado Direito 
        function container_titlelist { 
            $lb_container_titlelist = New-Object System.Windows.Forms.Label
            $lb_container_titlelist.Location = New-Object System.Drawing.Point(332, 10.5)
            $lb_container_titlelist.Size = New-Object System.Drawing.Size(229.5, 24)
            $lb_container_titlelist.BorderStyle = "None"
            $lb_container_titlelist.add_paint({ $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
        
            $lb_titlelist = New-Object System.Windows.Forms.Label
            $lb_titlelist.Location = New-Object System.Drawing.Point(380, 15.5)
            $lb_titlelist.Size = New-Object System.Drawing.Size(150, 17)
            $lb_titlelist.Text = 'SELECIONE AS FUNÇÕES'
            $lb_titlelist.Font = New-Object System.Drawing.Font('Inter', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
            $lb_titlelist.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
            # $lb_titlelist.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
    
                
            $suporte_GUI.controls.AddRange(@(   
                    $lb_titlelist, 
                    $lb_container_titlelist
                ))
        }

        $lb_container_list = New-Object System.Windows.Forms.Label
        $lb_container_list.Location = New-Object System.Drawing.Point(305, 33)
        $lb_container_list.Size = New-Object System.Drawing.Size(280, 240)
        $lb_container_list.BorderStyle = "None"
        $lb_container_list.add_paint({
                $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
            })
    
        $cb_list_function = New-Object system.Windows.Forms.CheckedListBox
        $cb_list_function.CheckOnClick = $true
        $cb_list_function.width = 270
        $cb_list_function.height = 245
        $cb_list_function.Anchor = 'top,right,left'
        $cb_list_function.BorderStyle = "None"
        $cb_list_function.location = New-Object System.Drawing.Point(310, 38)
        $cb_list_function.Font = New-Object System.Drawing.Font('Inter', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Regular))
        $cb_list_function.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#343434")
        $cb_list_function.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
        $suporte_GUI.controls.AddRange(@(   
                $cb_list_function,
                $lb_container_list
            ))
            
        function add_function_list {
            $cb_list_function.Items.Add("Ativar modo desempenho") | Out-Null
            $cb_list_function.Items.Add("Ativar visualizador de fotos do windows") | Out-Null
            $cb_list_function.Items.Add("Desabilitando serviços de inicialização") | Out-Null
            $cb_list_function.Items.Add("Desabilitar telemetria") | Out-Null
            $cb_list_function.Items.Add("Desabilitar Cortana") | Out-Null
            $cb_list_function.Items.Add("Desinstalar OneDrive") | Out-Null
            $cb_list_function.Items.Add("Desativar hibernação") | Out-Null
            $cb_list_function.Items.Add("Limpeza de Disco") | Out-Null
            $cb_list_function.Items.Add("Limpeza no Registro") | Out-Null
            $cb_list_function.Items.Add("Remover aplicativos nativos") | Out-Null
        }

        function container_vert_line {
            $lb_vert_line = New-Object System.Windows.Forms.Label
            $lb_vert_line.Location = New-Object System.Drawing.Point(286, 17)
            $lb_vert_line.Size = New-Object System.Drawing.Size(1, 340)
            $lb_vert_line.BorderStyle = "None"
            $lb_vert_line.add_paint({
                    $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                    $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                })
            $suporte_GUI.controls.AddRange(@(   
                    $lb_vert_line
                ))
        }

        $ProgressBar = New-Object system.Windows.Forms.ProgressBar
        $ProgressBar.width = 500
        $ProgressBar.height = 3
        $ProgressBar.location = New-Object System.Drawing.Point(25, 375)
        
        $lb_percent = New-Object System.Windows.Forms.Label
        $lb_percent.text = "0%"
        $lb_percent.width = 45
        $lb_percent.height = 20
        $lb_percent.location = New-Object System.Drawing.Point(530, 366)
        $lb_percent.TextAlign = "MiddleCenter"
        $lb_percent.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $lb_percent.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        
        $suporte_GUI.controls.AddRange(@(   
                $ProgressBar
                $lb_percent
            ))

        $checkbox_all_list = New-Object system.Windows.Forms.CheckBox
        $checkbox_all_list.text = "MARCAR TODOS"
        $checkbox_all_list.AutoSize = $False
        $checkbox_all_list.location = New-Object System.Drawing.Point(397, 285)
        $checkbox_all_list.Font = New-Object System.Drawing.Font('Arial Black', 7, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $checkbox_all_list.width = 140
        $checkbox_all_list.height = 17
        $checkbox_all_list.TextAlign = "MiddleLeft"
        $checkbox_all_list.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $suporte_GUI.controls.AddRange(@(   
                $checkbox_all_list
            ))

        $change_name_computer = New-Object system.Windows.Forms.Button
        $change_name_computer.text = "ALTERAR NOME DO COMPUTADOR"
        $change_name_computer.AutoSize = $false
        $change_name_computer.width = 240
        $change_name_computer.height = 40
        $change_name_computer.location = New-Object System.Drawing.Point(26, 215)
        $change_name_computer.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $change_name_computer.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $change_name_computer.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
        $suporte_GUI.controls.AddRange(@(   
                $change_name_computer
            ))
        
        $btn_windows_image = New-Object system.Windows.Forms.Button
        $btn_windows_image.text = "RECUPERAR IMAGEM DO WINDOWS"
        $btn_windows_image.AutoSize = $false
        $btn_windows_image.Visible = $true
        $btn_windows_image.width = 240
        $btn_windows_image.height = 40
        $btn_windows_image.location = New-Object System.Drawing.Point(26, 265)
        $btn_windows_image.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $btn_windows_image.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $btn_windows_image.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")

        $btn_cancel_windows_image = New-Object system.Windows.Forms.Button
        $btn_cancel_windows_image.text = "CANCELAR RECUPERAÇÃO"
        $btn_cancel_windows_image.AutoSize = $false
        $btn_cancel_windows_image.Visible = $False
        $btn_cancel_windows_image.width = 240
        $btn_cancel_windows_image.height = 40
        $btn_cancel_windows_image.location = New-Object System.Drawing.Point(26, 265)
        $btn_cancel_windows_image.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $btn_cancel_windows_image.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $btn_cancel_windows_image.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
        $suporte_GUI.controls.AddRange(@(   
                $btn_windows_image
                $btn_cancel_windows_image
            ))
    
        $btn_windows_errors = New-Object system.Windows.Forms.Button
        $btn_windows_errors.text = "CONSERTAR ERROS DO WINDOWS"
        $btn_windows_errors.Visible = $true
        $btn_windows_errors.width = 240
        $btn_windows_errors.height = 40
        $btn_windows_errors.TextAlign = "MiddleCenter"
        $btn_windows_errors.location = New-Object System.Drawing.Point(26, 315)
        $btn_windows_errors.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $btn_windows_errors.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $btn_windows_errors.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")

        $btn_cancel_windows_errors = New-Object system.Windows.Forms.Button
        $btn_cancel_windows_errors.text = "CANCELAR CONSERTO DE ERROS"
        $btn_cancel_windows_errors.Visible = $false
        $btn_cancel_windows_errors.width = 240
        $btn_cancel_windows_errors.height = 40
        $btn_cancel_windows_errors.TextAlign = "MiddleCenter"
        $btn_cancel_windows_errors.location = New-Object System.Drawing.Point(26, 315)
        $btn_cancel_windows_errors.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $btn_cancel_windows_errors.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $btn_cancel_windows_errors.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
        $suporte_GUI.controls.AddRange(@(   
                $btn_windows_errors,
                $btn_cancel_windows_errors
            ))

        $lb_log = New-Object System.Windows.Forms.Label
        $lb_log.Location = New-Object System.Drawing.Point(25, 380)
        $lb_log.Size = New-Object System.Drawing.Size(500, 15)
        $lb_log.Text = ''
        $lb_log.TextAlign = 'MiddleCenter'
        $lb_log.Font = New-Object System.Drawing.Font('Arial', 7, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $lb_log.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
        $suporte_GUI.controls.AddRange(@(   
                $lb_log
            ))

        $start_button = New-Object system.Windows.Forms.Button
        $start_button.text = "INICIAR"
        $start_button.width = 80
        $start_button.height = 35
        $start_button.location = New-Object System.Drawing.Point(337, 315)
        $start_button.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $start_button.TextAlign = 'MiddleCenter'
        $start_button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $start_button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")

        $cancel_button = New-Object system.Windows.Forms.Button
        $cancel_button.text = "FECHAR"
        $cancel_button.width = 80
        $cancel_button.height = 35
        $cancel_button.location = New-Object System.Drawing.Point(485, 315)
        $cancel_button.Font = New-Object System.Drawing.Font('Arial Black', 8, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $cancel_button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
        $cancel_button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")

        try {
            container_titleapp
            container_namecomputer
            container_ipcomputer
            container_titlelist
            add_function_list
            container_vert_line
        }
        catch {}
        $suporte_GUI.controls.AddRange(@(
                $start_button, 
                $cancel_button
            ))
        $suporte_GUI.KeyPreview = $true
        $suporte_GUI.Add_KeyDown({ 
                if ($_.KeyCode -eq "Escape") {
                    $suporte_GUI.Close()
                }

                if ($_.KeyCode -eq "Enter") {
                    $start_button.PerformClick()
                }
            })

        $checkbox_all_list.Add_CheckStateChanged({
                if ($checkbox_all_list.Checked) {
                    $cb_list_function.Text = "DESMARCAR TODOS"
                    $cb_list_function.SetItemChecked(0, 1)
                    $cb_list_function.SetItemChecked(1, 1)
                    $cb_list_function.SetItemChecked(2, 1)
                    $cb_list_function.SetItemChecked(3, 1)
                    $cb_list_function.SetItemChecked(4, 1)
                    $cb_list_function.SetItemChecked(5, 1)
                    $cb_list_function.SetItemChecked(6, 1)
                    $cb_list_function.SetItemChecked(7, 1)
                    $cb_list_function.SetItemChecked(8, 1)
                    $cb_list_function.SetItemChecked(9, 1)

                }
                else {
                    $checkbox_all_list.Text = "MARCAR TODOS"
                    $cb_list_function.SetItemChecked(0, 0)
                    $cb_list_function.SetItemChecked(1, 0)
                    $cb_list_function.SetItemChecked(2, 0)
                    $cb_list_function.SetItemChecked(3, 0)
                    $cb_list_function.SetItemChecked(4, 0)
                    $cb_list_function.SetItemChecked(5, 0)
                    $cb_list_function.SetItemChecked(6, 0)
                    $cb_list_function.SetItemChecked(7, 0)
                    $cb_list_function.SetItemChecked(8, 0)
                    $cb_list_function.SetItemChecked(9, 0)

                }
            })

        $change_name_computer.Add_Click({ 

                $newname_GUI = New-Object system.Windows.Forms.Form
                $newname_GUI.ClientSize = New-Object System.Drawing.Point(300, 150)
                $newname_GUI.text = "Limpeza e Suporte"
                $newname_GUI.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#343434")
                $newname_GUI.FormBorderStyle = 'Fixed3D'
                $newname_GUI.Icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command powershell).Path)
                $newname_GUI.StartPosition = "CenterScreen"
                $newname_GUI.Opacity = .98
                $newname_GUI.MaximizeBox = $false

                
                $lb_container_newnamecomputer = New-Object System.Windows.Forms.Label
                $lb_container_newnamecomputer.Location = New-Object System.Drawing.Point(20, 10)
                $lb_container_newnamecomputer.Size = New-Object System.Drawing.Size(260, 100)
                $lb_container_newnamecomputer.BorderStyle = "None"
                $lb_container_newnamecomputer.add_paint({ $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 2)
                        $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                    })
                
                $lb_title_newcomputername = New-Object System.Windows.Forms.Label
                $lb_title_newcomputername.Location = New-Object System.Drawing.Point(35, 20)
                $lb_title_newcomputername.Size = New-Object System.Drawing.Size(230, 14)
                $lb_title_newcomputername.Text = 'ALTERAR NOME DO COMPUTADOR'
                $lb_title_newcomputername.Font = New-Object System.Drawing.Font('Inter', 9, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
                $lb_title_newcomputername.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
                $lb_title_newcomputername.TextAlign = 'MiddleCenter'

                $line_newcomputername = New-Object System.Windows.Forms.Label
                $line_newcomputername.Location = New-Object System.Drawing.Point(30, 40)
                $line_newcomputername.Size = New-Object System.Drawing.Size(240, 1)
                $line_newcomputername.BorderStyle = "None"
                $line_newcomputername.add_paint({
                        $whitePen = new-object System.Drawing.Pen([system.drawing.color]::white, 1)
                        $_.graphics.drawrectangle($whitePen, $this.clientrectangle)
                    })
        
                $textBox_newcomputername = New-Object System.Windows.Forms.TextBox
                $textBox_newcomputername.Location = New-Object System.Drawing.Point(35, 60)
                $textBox_newcomputername.Size = New-Object System.Drawing.Size(230, 60)
                $textBox_newcomputername.TextAlign = "Center"
                $textBox_newcomputername.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#fff")
                $textBox_newcomputername.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#343434")
                $textBox_newcomputername.Font = New-Object System.Drawing.Font('Inter', 15, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
                $textBox_newcomputername.CharacterCasing = 'Upper'
                $textBox_newcomputername.Add_KeyDown({
                        if ($_.KeyCode -eq "Space") {
                            $_.SuppressKeyPress = $true
                        }            
                    })

                $btn_change_name = New-Object system.Windows.Forms.Button
                $btn_change_name.text = "ALTERAR"
                $btn_change_name.width = 75
                $btn_change_name.height = 30
                $btn_change_name.location = New-Object System.Drawing.Point(180, 115)
                $btn_change_name.Font = New-Object System.Drawing.Font('Arial Black', 7.3, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
                $btn_change_name.TextAlign = 'MiddleCenter'
                $btn_change_name.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
                $btn_change_name.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $btn_change_name.Add_Click({

                        $rename_result = Rename-Computer -NewName $textBox_newcomputername.Text -Force -PassThru
                        $hassucceded = $rename_result.HasSucceeded.ToString()
                        # $oldcomputername = $rename_result.OldComputerName.ToString()
                        # $newcomputername = $rename_result.NewComputerName.ToString()

                        if ($hassucceded -eq "True") {
                            $restart = [System.Windows.Forms.MessageBox]::Show('As mudanças so terão efeito após a reinicialização do sistema. Deseja reiniciar agora ?' , "Alteração concluida" , 4)
                            if ($restart -eq 'Yes') {
                                shutdown -r -t 0 -f
                            }
                            else { 
                                $newname_GUI.Close()
                            }
                        }
                        elseif ($hassucceded -eq "False") {
                            [System.Windows.Forms.MessageBox]::Show("Você não tem permissão para executar essa alteração", "Erro", "Ok", "Error")
                        }  
                    })

                $btn_cancel = New-Object system.Windows.Forms.Button
                $btn_cancel.text = "FECHAR"
                $btn_cancel.width = 75
                $btn_cancel.height = 30
                $btn_cancel.location = New-Object System.Drawing.Point(45, 115)
                $btn_cancel.Font = New-Object System.Drawing.Font('Arial Black', 7.3, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
                $btn_cancel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
                $btn_cancel.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $btn_cancel.Add_Click({
                        $newname_GUI.Close()
                    })
    
                $newname_GUI.controls.AddRange(@(     
                        $btn_cancel,
                        $textBox_newcomputername, 
                        $btn_change_name,
                        $line_newcomputername,
                        $lb_title_newcomputername,
                        $lb_container_newnamecomputer    
                    ))

                $newname_GUI.Add_Shown({ $textBox_newcomputername.Select() })
                $newname_GUI.Refresh()
                [void]$newname_GUI.ShowDialog()
                
            })
    
        $change_name_computer.Add_MouseEnter({ 
                $change_name_computer.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $change_name_computer.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })
    
        $change_name_computer.Add_MouseLeave({ 
                $change_name_computer.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $change_name_computer.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })

        $tick_Dism = {

            $job_dism = get-job jobdism
            $content = get-content -Path 'Dism.log' 

            if ($job_dism.State -ne "Completed") {
                $count = ($content | Select-String -Pattern '%' -AllMatches)
                $percent = ($count[$count.count - 1].Line.Substring('28', '4')).Replace("%", "")

                $lb_percent.text = $percent + "%"
                $ProgressBar.Value = $percent       
                $lb_log.text = "Executando restauração e limpeza de imagem do windows..."
            } 

            if ($job_dism.State -eq "Completed") {
                
                $timer_Dism.stop()
                $errodism = ($content | Select-String -Pattern 'Erro' -AllMatches).Line.Substring('5', '4').Replace(' ', '')
                $lb_log.text = "Processo finalizado..."
                
                if ($errodism.count -ne 0) {
                    $btn_cancel_windows_image.Visible = $false
                    $btn_windows_image.Visible = $true
                    $result = [System.Windows.Forms.MessageBox]::Show("Erro - $errodism", 'Erro', 0)
                    if ($result -eq 'OK') {
                        $ProgressBar.Value = 0
                        $lb_percent.text = "0%"
                        $lb_log.Text = ""
                    } 
                } 
                else {
                    $ProgressBar.Value = 100
                    $lb_percent.text = "100%"
                    $lb_log.text = "Processo completo..."

                    $result = [System.Windows.Forms.MessageBox]::Show('Recuperação de imagem do windows completa' , "Tarefa Completada" , 0)
                    if ($result -eq 'OK') {
                        $ProgressBar.Value = 0
                        $lb_percent.text = "0%"
                        $lb_log.text = ""
                    } 
                }
                Remove-Item -Force "Dism.log"
                Get-Job jobdism | stop-job -f
                Get-Job jobdism | Remove-Job
                $btn_cancel_windows_image.Visible = $false
                $btn_windows_image.Visible = $true
            }
        }

        $tick_sfc = {

            $job_sfc = get-job jobsfc

            if ($job_sfc.State -ne "Completed") {
                $content = get-content -Path 'sfc.log' -Encoding unicode | Where-Object { $_ }
                $count = ($content | Select-String -Pattern '%' -AllMatches)
                $percent = ($count[$count.count - 1].Line.Substring('11', '4')).Replace("%", "").Replace(" ", "")
                $percent += ($count[$count.count - 1].Line.Substring('27', '1')).Replace("%", "").Replace(" ", "")
                $percent += ($count[$count.count - 1].Line.Substring('29', '1')).Replace("%", "").Replace(" ", "")

                $lb_percent.text = $percent + "%"
                $ProgressBar.Value = $percent
                $lb_log.text = "Corrigindo problemas do windows..."

            } 

            if ($job_sfc.State -eq "Completed") {
                
                $timer_sfc.Stop()
            
                $ProgressBar.Value = 100
                $lb_percent.text = "100%"
                $lb_log.text = "Processo completo..."

                $result = [System.Windows.Forms.MessageBox]::Show('Correções do windows foram aplicadas' , "Tarefa Completada" , 0)
                if ($result -eq 'OK') {
                    $ProgressBar.Value = 0
                    $lb_percent.text = "0%"
                    $lb_log.text = ""
                } 
                
                Remove-Item -Force "sfc.log"
                Get-Job jobsfc | stop-job -force
                Get-Job jobsfc | Remove-Job -force

                $btn_cancel_windows_errors.Visible = $false
                $btn_windows_errors.Visible = $true
            }
        }

        # timer_Dism config
        $timer_Dism.Interval = 1000
        $timer_Dism.add_Tick($tick_Dism)

        $timer_sfc.Interval = 1000
        $timer_sfc.add_Tick($tick_sfc)


        $btn_windows_image.Add_Click({ 
                $btn_cancel_windows_image.Visible = $true
                $btn_windows_image.Visible = $False
                $lb_log.text = 'Iniciando Limpeza do Windows...'

                Start-Job -ScriptBlock {
                    DISM.exe /Online /Cleanup-image /Restorehealth /LogLevel:4 >> Dism.log
                } -Name "jobdism"
                
                $timer_Dism.Interval = 1000
                $timer_Dism.Start()
                $lb_log.Text = "Processando..."
                $ProgressBar.Value = 0
                $lb_percent.text = "0%"

            })
        $btn_windows_image.Add_MouseEnter({ 
                $btn_windows_image.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $btn_windows_image.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })
        $btn_windows_image.Add_MouseLeave({ 
                $btn_windows_image.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $btn_windows_image.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })


        $btn_cancel_windows_image.Add_Click({ 
                $timer_Dism.stop()
                $this.Visible = $False
                $btn_windows_image.Visible = $true
                Get-Job jobdism | stop-job
                Get-Job jobdism | Remove-Job
                Remove-Item Dism.log
                $lb_percent.Text = "0%"
                $ProgressBar.Value = 0
                $lb_log.Text = "Limpeza Cancelada"
                Start-Sleep -Seconds 1
                $lb_log.Text = ""

            })
        $btn_cancel_windows_image.Add_MouseEnter({ 
                $btn_windows_image.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $btn_windows_image.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })
        $btn_cancel_windows_image.Add_MouseLeave({ 

                $btn_windows_image.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $btn_windows_image.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })


        $btn_windows_errors.Add_Click({ 


                $btn_cancel_windows_errors.Visible = $true
                $btn_windows_errors.Visible = $False

                $lb_log.text = 'Iniciando verificação do Windows...'
                Start-Job -ScriptBlock {


                    Start-Process -FilePath "C:\Windows\System32\sfc.exe" -ArgumentList '/scannow' -Wait -NoNewWindow -RedirectStandardOutput sfc.log 

                } -Name "jobsfc" -Verbose
                
                $timer_sfc.Start()
                $lb_log.Text = "Processando..."
                $ProgressBar.Value = 0
                $lb_percent.text = "0%"
        
            })
        $btn_windows_errors.Add_MouseEnter({ 
                $btn_windows_errors.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $btn_windows_errors.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })
        $btn_windows_errors.Add_MouseLeave({ 
                $btn_windows_errors.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $btn_windows_errors.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })


        $btn_cancel_windows_errors.Add_Click({ 
                $btn_cancel_windows_errors.Visible = $false
                $btn_windows_errors.Visible = $true

                $timer_sfc.Stop()
                Get-Job jobsfc | Stop-Job
                Get-Job jobsfc | Remove-Job
                Remove-Item sfc.log

                $lb_percent.Text = "0%"
                $ProgressBar.Value = 0
                $lb_log.Text = "Correção de problemas cancelada"
                Start-Sleep -Seconds 1
                $lb_log.Text = ""
            
            })
        $btn_cancel_windows_errors.Add_MouseEnter({ 
                $btn_cancel_windows_errors.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $btn_cancel_windows_errors.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })
        $btn_cancel_windows_errors.Add_MouseLeave({ 

                $btn_cancel_windows_errors.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $btn_cancel_windows_errors.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })


        $cancel_button.Add_Click({ 

                $suporte_GUI.close()
        
            })
        $cancel_button.Add_MouseEnter({ 
                $cancel_button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $cancel_button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })
        $cancel_button.Add_MouseLeave({ 
                $cancel_button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $cancel_button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })
    

        $start_button.Add_Click({
                $selected = $cb_list_function.CheckedItems -join "`r`n"
                $cont_max = 0
                $restart = $false

                # Contando itens 
                foreach ($item in $cb_list_function.CheckedItems) {
                    $cont_max ++
                }

                # Condição nada selecionado 
                if (!$selected) {
                    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                    [System.Windows.Forms.MessageBox]::Show('Você não selecionou nenhum item' , "Erro" , 0)
                }

                # Condições Lista de funções
                if ($selected.Contains("Ativar visualizador de fotos do windows")) {

                    Start-Job -ScriptBlock {

                        $lb_log.text = 'Adicionando visualizador de fotos do windows...'

                        REG ADD "HKCU\SOFTWARE\Classes\.ico"  /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
                        REG ADD "HKCU\SOFTWARE\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
                        REG ADD "HKCU\SOFTWARE\Classes\.bmp"  /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
                        REG ADD "HKCU\SOFTWARE\Classes\.png"  /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
                        REG ADD "HKCU\SOFTWARE\Classes\.gif"  /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 
                        REG ADD "HKCU\SOFTWARE\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
                        REG ADD "HKCU\SOFTWARE\Classes\.jpg"  /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f 

                        $lb_log.text = 'Visualizador de fotos do windows Adicionado...'

                    } -Name "jobvisualizerphotos"

                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Desativar hibernação")) {

                    $lb_log.text = 'Desativando Hibernação...'

                    powercfg.exe /hibernate off | Out-Null
                    Remove-Item -force Null

                    $lb_log.text = 'Hibernação Desativada...'

                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Ativar modo desempenho")) {

                    Start-Job -ScriptBlock {
                        $lb_log.text = 'Coletando esquemas de energia...'
                        $powerscheme = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power
                        
                        #Ativando um esquema de energia "Equilibrado"
                        foreach ($scheme in $powerscheme) { 
                            if ($scheme.ElementName -eq "Equilibrado") { 
                                powercfg /SETACTIVE $scheme.InstanceID.Substring("21", $scheme.InstanceID.Length - 22) 
                            } 
                        }

                        #removendo Desempenho máximo duplicado
                        for ($i = 0; $i -lt $powerscheme.Count; $i++) {
                            if ($powerscheme[$i].ElementName -eq "Desempenho Máximo") {
                                powercfg /delete $powerscheme[$i].InstanceID.Substring("21", $powerscheme[$i].InstanceID.Length - 22)
                            }
                        }
                    
                        #Duplicando esquema Desempenho maximo do windows
                        $lb_log.text = 'Criando de desempenho máximo...'
                        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
                
                        #Atualizando tabela
                        $lb_log.text = 'Coletando novas informações...'
                        $powerscheme = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power
                
                        #Ativando esquema criado
                        $lb_log.text = 'Ativando desempenho máximo...'
                        for ($i = 0; $i -lt $powerscheme.Count; $i++) {
                            if ($powerscheme[$i].ElementName -eq "Desempenho Máximo") {
                                powercfg /SETACTIVE $powerscheme[$i].InstanceID.Substring("21", $powerscheme[$i].InstanceID.Length - 22)
                            }
                        }
                
                        $planned = @(
                            "monitor-timeout-ac"
                            "monitor-timeout-dc"
                            "disk-timeout-ac"
                            "disk-timeout-dc"
                            "standby-timeout-ac"
                            "standby-timeout-dc"
                            "hibernate-timeout-ac"
                            "hibernate-timeout-dc"
                        )
                
                        foreach ($plan in $planned) {
                            $lb_log.text = "Alterando " + $plan + " para desativado"
                            powercfg /change $plan 0
                        }
                
                        try {
                            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Value 3
                            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name UserPreferencesMask -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x12, 0x00, 0x00, 0x00))
                        }
                        catch {}
                
                        $lb_log.text = 'Modo desempenho ativado...'
                        Remove-Item -force Null
                    } -Name "jobmaxperformance"

                    $restart = $true
                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Remover aplicativos nativos")) {

                    Start-Job -ScriptBlock {

                        $ErrorActionPreference = 'SilentlyContinue'
                        Function Sysprep {
                
                            # Disable Windows Store Automatic Updates
                            $lb_log.text = 'Desabilitando atualização automatica da Windows Store...'
                            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
                            If (!(Test-Path $registryPath)) {
                                Mkdir $registryPath
                                New-ItemProperty $registryPath AutoDownload -Value 2 
                            }
                            Set-ItemProperty $registryPath AutoDownload -Value 2
                
                            #Stop WindowsStore Installer Service and set to Disabled
                            $lb_log.text = 'Parando Serviço de instalação...'
                            Stop-Service InstallService
                
                            $lb_log.text = 'Configurando inicio do Serviço de instalação para desabilitado...'
                            Set-Service InstallService -StartupType Disabled
                        }
                
                        $lb_log.text = 'Checando DMW Serviço...'
                        Function CheckDMWService {
                
                            Param([switch]$Debloat)
                
                            If (Get-Service dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
                                Set-Service dmwappushservice -StartupType Automatic
                            }
                
                            If (Get-Service dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
                                Start-Service dmwappushservice
                            } 
                        }
                
                        Function DebloatAll {
                            $lb_log.text = 'Removendo aplicativos nativos...'
                            #Removes AppxPackages
                            Get-AppxPackage | Where-Object { !($_.Name -cmatch $global:WhiteListedAppsRegex) -and !($NonRemovables -cmatch $_.Name) } | Remove-AppxPackage
                            Get-AppxProvisionedPackage -Online | Where-Object { !($_.DisplayName -cmatch $global:WhiteListedAppsRegex) -and !($NonRemovables -cmatch $_.DisplayName) } | Remove-AppxProvisionedPackage -Online
                            Get-AppxPackage -AllUsers | Where-Object { !($_.Name -cmatch $global:WhiteListedAppsRegex) -and !($NonRemovables -cmatch $_.Name) } | Remove-AppxPackage
                            $lb_log.text = 'Aplicativos nativos removidos...'
                        }
                
                        #Creates a PSDrive to be able to access the 'HKCR' tree
                        $lb_log.text = 'Criando PSDrive para acessar o registro ROOT...'
                        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                
                        $lb_log.text = 'Criando chaves de remoção de registro...'
                        Function Remove-Keys {         
                            #These are the registry keys that it will delete.
                            $Keys = @(
                      
                                #Remove Background Tasks
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                      
                                #Windows File
                                "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                      
                                #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                      
                                #Scheduled Tasks to delete
                                "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                      
                                #Windows Protocol Keys
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                         
                                #Windows Share Target
                                "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                            )
                  
                            #This writes the output of each key it is removing and also removes the keys listed above.
                            ForEach ($Key in $Keys) {
                                $lb_log.text = "Removing $Key from registry"
                                Remove-Item $Key -Recurse
                            }
                        }
                
                        Function Protect-Privacy { 
                            
                            #Creates a PSDrive to be able to access the 'HKCR' tree
                            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                
                            $lb_log.text = 'Desabilitando Windows Feedback Experience...'
                            #Disables Windows Feedback Experience
                            $Advertising = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
                            If (Test-Path $Advertising) {
                                Set-ItemProperty $Advertising Enabled -Value 0
                            }
                      
                            #Stops Cortana from being used as part of your Windows Search Function
                            $lb_log.text = 'Desabilitando cortana das pesquisas...'
                            $Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                            If (Test-Path $Search) {
                                Set-ItemProperty $Search AllowCortana -Value 0
                            }
                      
                            #Stops the Windows Feedback Experience from sending anonymous data
                            $lb_log.text = 'Desativando o Windows feedback experience de enviar dados anonymous...'
                            $Period1 = 'HKCU:\Software\Microsoft\Siuf'
                            $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
                            $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
                            If (!(Test-Path $Period3)) { 
                                mkdir $Period1
                                mkdir $Period2
                                mkdir $Period3
                                New-ItemProperty $Period3 PeriodInNanoSeconds -Value 0
                            }
                             
                            #Prevents bloatware applications from returning
                            $lb_log.text = 'Adicionando chave do registro para prevenir a volta dos apps removidos...'
                            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
                            If (!(Test-Path $registryPath)) {
                                Mkdir $registryPath
                                New-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 
                            }          
                  
                            $lb_log.text = 'Permitindo remoção do Mixed Reality Portal...'
                            $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
                            If (Test-Path $Holo) {
                                Set-ItemProperty $Holo FirstRunSucceeded -Value 0
                            }
                  
                            #Disables live tiles
                            $lb_log.text = 'Desabilitando Live tiles...'
                            $Live = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
                            If (!(Test-Path $Live)) {
                                mkdir $Live  
                                New-ItemProperty $Live NoTileApplicationNotification -Value 1
                            }
                  
                            #Turns off Data Collection via the AllowTelemtry key by changing it to 0
                            $lb_log.text = 'Desativando coleçã de dados via telemetria...'
                            $DataCollection = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
                            If (Test-Path $DataCollection) {
                                Set-ItemProperty $DataCollection AllowTelemetry -Value 0
                            }
                  
                            #Disables People icon on Taskbar
                            $lb_log.text = 'Desabilitando Icones de pessoas na barra de tarefas...'
                            $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
                            If (Test-Path $People) {
                                Set-ItemProperty $People PeopleBand -Value 0
                            }
                
                            #Disables suggestions on start menu
                            $lb_log.text = 'Desabilitando sugestões no menu inicial...'
                            $Suggestions = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    
                            If (Test-Path $Suggestions) {
                                Set-ItemProperty $Suggestions SystemPaneSuggestionsEnabled -Value 0
                            }
                        
                            # Desabilitando pesquisa do Bing via menu de inicio
                            $lb_log.text = 'Desabilitando pesquisa do Bing via menu de inicio...'
                            $BingSearch = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                            If (Test-Path $BingSearch) {
                                Set-ItemProperty $BingSearch DisableSearchBoxSuggestions -Value 1
                            }
                        
                            $lb_log.text = 'Removendo CloudStore...'
                            $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
                            If (Test-Path $CloudStore) {
                                Stop-Process Explorer.exe -Force
                                Remove-Item $CloudStore -Recurse -Force
                                Start-Process Explorer.exe -Wait
                            }
                
                            #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
                            reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
                            Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
                            Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
                            Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
                            reg unload HKU\Default_User
                  
                            $lb_log.text = 'Desabilitando tarefas que são desnecessárias...'
                            #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask
                            Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask
                            Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask
                            Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask
                            Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask
                            Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask
                        }
                
                        Function UnpinStart {
                            # https://superuser.com/a/1442733
                            # Requires -RunAsAdministrator
                
                            $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
<DefaultLayoutOverride>
    <StartLayoutCollection>
        <defaultlayout:StartLayout GroupCellWidth="6" />
    </StartLayoutCollection>
</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
                
                            $layoutFile = "C:\Windows\StartMenuLayout.xml"
                
                            #Delete layout file if it already exists
                            If (Test-Path $layoutFile) {
                                Remove-Item $layoutFile
                            }
                
                            #Creates the blank layout file
                            $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII
                
                            $regAliases = @("HKLM", "HKCU")
                
                            #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
                            foreach ($regAlias in $regAliases) {
                                $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
                                $keyPath = $basePath + "\Explorer" 
                                IF (!(Test-Path -Path $keyPath)) { 
                                    New-Item -Path $basePath -Name "Explorer"
                                }
                                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
                                Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
                            }
                
                            #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
                            Stop-Process -name explorer
                            Start-Sleep -s 5
                            $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
                            Start-Sleep -s 5
                
                            #Enable the ability to pin items again by disabling "LockedStartLayout"
                            foreach ($regAlias in $regAliases) {
                                $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
                                $keyPath = $basePath + "\Explorer" 
                                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
                            }
                
                            #Restart Explorer and delete the layout file
                            Stop-Process -name explorer
                
                            # Uncomment the next line to make clean start menu default for all new users
                            Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
                
                            Remove-Item $layoutFile
                        }
                        Function CheckInstallService {
                
                            If (Get-Service InstallService | Where-Object { $_.Status -eq "Stopped" }) {  
                                Start-Service InstallService
                                Set-Service InstallService -StartupType Automatic 
                            }
                        }
                
                        $lb_log.text = 'Iniciando preparação do sistema...'
                        Sysprep
                
                        $lb_log.text = 'Removendo apps desnecessários...'
                        DebloatAll
                
                        $lb_log.text = 'Removendo chaves de registro...'
                        Remove-Keys
                
                        Protect-Privacy
                        UnpinStart
                        CheckDMWService
                        CheckInstallService
                        $lb_log.text = 'Apps nativos desinstalados...'

                    } -Name "jobremovenativeapp"

                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Desabilitando serviços de inicialização")) {
                    
                    Start-Job -ScriptBlock {

                        $lb_log.text = "Desabilitando Serviços de Inicialização..."
    
                        #Desativando SysMain
                        sc config SysMain start= disabled | Out-Null
                    
                        #Desativando WSearch
                        # sc config WSearch start= disabled | Out-Null
                        sc config MicrosoftEdgeElevationService start= disabled | Out-Null
                        sc config edgeupdate start= disabled | Out-Null
                        sc config edgeupdatem start= disabled | Out-Null
                        sc config GoogleChromeElevationService start= disabled | Out-Null
                        sc config gupdate start= disabled | Out-Null
                        sc config gupdatem start= disabled | Out-Null
                        sc config XboxGipSvc start= disabled | Out-Null
                    
                        #Desabilitando WinSAT do agendador de tarefas
                        schtasks /change /TN '\Microsoft\Windows\Maintenance\WinSAT' /disable | Out-Null
                    
                        Remove-Item -force Null
                        $lb_log.text = "Serviços desativados na inicialização..."

                    } -Name "jobdistartservices"

                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Limpeza no Registro")) {
                    Change_register

                    Start-Job -ScriptBlock {

                        $lb_log.text = "Realizando as alterações no registro do computador"
                        #Alterando inicialização do NDU
                        REG ADD HKLM\SYSTEM\ControlSet001\Services\Ndu /v start /t REG_DWORD /d 4 /f | Out-Null
                             
                        #Alterando inicialização dp DOSVC
                        REG ADD HKLM\SYSTEM\CurrentControlSet\Services\DoSvc /v Start /t REG_DWORD /d 4 /f | Out-Null
                        
                        # Alterando inicialização do task schedule 
                        REG ADD HKLM\SYSTEM\SYSTEM\CurrentControlSet\Services\Schedule /V start /T REG_DWORD /D 2 /F | Out-Null
                        
                        #Alterando inicialização dp TimeBrokerSvc
                        REG ADD HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc /V start /T REG_DWORD /D 2 /F | Out-Null
                        
                        # Desativando Aplicações em Segundo plano 
                        REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Acelerando desligamento 
                        REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f | Out-Null
                        
                        #Escodendo caixa de pesquisa do windows
                        #0 = hide completely, 1 = show only icon, 2 = show long search box
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando OneDrive na Inicialização    
                        REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /F 2> Null
                        
                        #Desativando Windows Error Reporting
                        schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable | Out-Null
                          
                        #Desativando Otimização de Entrega
                        REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 3 /f | Out-Null
                        REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando Modo Hotspot
                        REG ADD "HKLM\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v OsuRegistrationStatus /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando Historico de Arquivos
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando Dicas do Windows
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando Ajuda Ativa
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando Logs
                        REG ADD "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando FeedBack do Windows
                        REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando FeedBack de Ajuda do Windows 
                        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando FeedBack de Escrita
                        REG ADD "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando Programas do Windows Insider
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando Telemetria do Office 
                        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando Estatisticas do Windows Media Player
                        REG ADD "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Removendo 3D Builder do menu de Contexto
                        REG DELETE "HKEY_CLASSES_ROOT\SystemFileAssociations\.bmp\Shell\T3D Print" /f 2> Null
                        REG DELETE "HKEY_CLASSES_ROOT\SystemFileAssociations\.png\Shell\T3D Print" /f 2> Null
                        REG DELETE "HKEY_CLASSES_ROOT\SystemFileAssociations\.jpg\Shell\T3D Print" /f 2> Null
                        
                        #Ativando Meu Computador em vez do Acesso Rapido
                        #1 = Meu Computador | 2 = Acesso Rapido
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando Arquivos usados Recentemente no Acesso Rapido
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando Pastas usadas com frequencia no Acesos Rapido
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativando ID de Anuncio
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f | Out-Null
                        
                        #Desativando Mostrar conteudo Sugerido e APPS Pré Instalados
                        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /V DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /T REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RemediationRequired /T REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Desativa Localização do Windows
                        REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f | Out-Null
                        
                        #Melhorando Performance do Explorer
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f | Out-Null
                        
                        #Configurando Explorer
                        REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f | Out-Null
                        REG ADD "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ServerAdminUI /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DontPrettyPath /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v MapNetDrvBtn /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTypeOverlay /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowStatusBar /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 1 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v  PeopleBand /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarGlomLevel /t REG_DWORD /d 0 /f | Out-Null
                        REG ADD "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f | Out-Null
                        
                        function remove_keys {
                            $ErrorActionPreference = 'SilentlyContinue'
                            $Keys = @(
                                    
                                New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                                #Remove Background Tasks
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                                    
                                #Windows File
                                "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                    
                                #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                                    
                                #Scheduled Tasks to delete
                                "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
                                    
                                #Windows Protocol Keys
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
                                "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
                                       
                                #Windows Share Target
                                "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
                            )
                                
                            #This writes the output of each key it is removing and also removes the keys listed above.
                            ForEach ($Key in $Keys) {
                                $lb_log.text = "Removing $Key from registry"
                                Remove-Item $Key -Recurse
                            }
                            $lb_log.text = "Additional apps keys have been removed!"
                        }
                    
                        REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ctfmon /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f | Out-Null
                        $lb_log.text = ("Registro Modificado...")
                            
                        remove_keys
                        Remove-Item -force Null
                        

                    } -Name "jobchangeregist"

                    $restart = $true
                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Limpeza de Disco")) {

                    Start-Job -ScriptBlock {

                        $lb_log.text = "Limpando pastas temporarias..."
        
                        Remove-Item C:\\Temp\* -force -recurse 2> Null
                        Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files" -force -recurse 2> Null
                        Remove-Item $env:TEMP\* -force -recurse 2> Null
                        Remove-Item $env:windir\Temp\* -recurse -force 2> Null
                        Remove-Item $env:windir\Prefetch\* -recurse -force 2> Null
                        Remove-Item $env:windir\SoftwareDistribution\Download\* -recurse -force 2> Null
                        Remove-Item $env:windir\SystemTemp\* -recurse -force 2> Null
        
                        $lb_log.text = "Utilizando limpador do windows..."
                        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' | ForEach-Object {
                            New-ItemProperty -Path $_.PSPath -Name StateFlags0001 -Value 2 -PropertyType DWord -Force 2> Null
                        } 2> Null; 
                        Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -PassThru 2> Null

                        Remove-Item -force Null

                    } -Name "jobremtrash"

                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Desinstalar OneDrive")) {

                    Remove_onedrive

                    $restart = $true
                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Desabilitar telemetria")) {

                    Start-Job -ScriptBlock {

                        $ErrorActionPreference = 'SilentlyContinue'
                        #Disables Windows Feedback Experience
                        $lb_log.text = "Disabling Windows Feedback Experience program..."
                        $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
                        If (Test-Path $Advertising) {
                            Set-ItemProperty $Advertising Enabled -Value 0 
                        }
                                
                        #Stops Cortana from being used as part of your Windows Search Function
                        $lb_log.text = "Stopping Cortana from being used as part of your Windows Search Function"
                        $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                        If (Test-Path $Search) {
                            Set-ItemProperty $Search AllowCortana -Value 0 
                        }
                    
                        #Disables Web Search in Start Menu
                        $lb_log.text = "Disabling Bing Search in Start Menu"
                        $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
                        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
                        If (!(Test-Path $WebSearch)) {
                            New-Item $WebSearch
                        }
                        Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
                                
                        #Stops the Windows Feedback Experience from sending anonymous data
                        $lb_log.text = "Stopping the Windows Feedback Experience program"
                        $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
                        If (!(Test-Path $Period)) { 
                            New-Item $Period
                        }
                        Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 
                    
                        #Prevents bloatware applications from returning and removes Start Menu suggestions               
                        $lb_log.text = "Adding Registry key to prevent bloatware apps from returning"
                        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
                        $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                        If (!(Test-Path $registryPath)) { 
                            New-Item $registryPath
                        }
                        Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 
                    
                        If (!(Test-Path $registryOEM)) {
                            New-Item $registryOEM
                        }
                        Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0 
                        Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0 
                        Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0 
                        Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0 
                        Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0 
                        Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0          
                        
                        #Preping mixed Reality Portal for removal    
                        $lb_log.text = "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
                        $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
                        If (Test-Path $Holo) {
                            Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
                        }
                    
                        #Disables Wi-fi Sense
                        $lb_log.text = "Disabling Wi-Fi Sense"
                        $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
                        $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
                        $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
                        If (!(Test-Path $WifiSense1)) {
                            New-Item $WifiSense1
                        }
                        Set-ItemProperty $WifiSense1  Value -Value 0 
                        If (!(Test-Path $WifiSense2)) {
                            New-Item $WifiSense2
                        }
                        Set-ItemProperty $WifiSense2  Value -Value 0 
                        Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
                            
                        #Disables live tiles
                        $lb_log.text = "Disabling live tiles"
                        $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
                        If (!(Test-Path $Live)) {      
                            New-Item $Live
                        }
                        Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
                            
                        #Turns off Data Collection via the AllowTelemtry key by changing it to 0
                        $lb_log.text = "Turning off Data Collection"
                        $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
                        $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
                        $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
                        If (Test-Path $DataCollection1) {
                            Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
                        }
                        If (Test-Path $DataCollection2) {
                            Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
                        }
                        If (Test-Path $DataCollection3) {
                            Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
                        }
                        
                        #Disabling Location Tracking
                        $lb_log.text = "Disabling Location Tracking"
                        $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
                        $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
                        If (!(Test-Path $SensorState)) {
                            New-Item $SensorState
                        }
                        Set-ItemProperty $SensorState SensorPermissionState -Value 0 
                        If (!(Test-Path $LocationConfig)) {
                            New-Item $LocationConfig
                        }
                        Set-ItemProperty $LocationConfig Status -Value 0 
                            
                        #Disables People icon on Taskbar
                        $lb_log.text = "Disabling People icon on Taskbar"
                        $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
                        If (Test-Path $People) {
                            Set-ItemProperty $People -Name PeopleBand -Value 0
                        } 
                            
                        #Disables scheduled tasks that are considered unnecessary 
                        $lb_log.text = "Disabling scheduled tasks"
                        #Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask
                        Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask
                        Get-ScheduledTask Consolidator | Disable-ScheduledTask
                        Get-ScheduledTask UsbCeip | Disable-ScheduledTask
                        Get-ScheduledTask DmClient | Disable-ScheduledTask
                        Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask
                    
                        #$lb_log.text = "Uninstalling Telemetry Windows Updates"
                        #Uninstalls Some Windows Updates considered to be Telemetry. !WIP!
                        #Wusa /Uninstall /KB:3022345 /norestart /quiet
                        #Wusa /Uninstall /KB:3068708 /norestart /quiet
                        #Wusa /Uninstall /KB:3075249 /norestart /quiet
                        #Wusa /Uninstall /KB:3080149 /norestart /quiet        
                    
                        $lb_log.text = "Stopping and disabling WAP Push Service"
                        #Stop and disable WAP Push Service
                        Stop-Service "dmwappushservice"
                        Set-Service "dmwappushservice" -StartupType Disabled
                    
                        $lb_log.text = "Stopping and disabling Diagnostics Tracking Service"
                        #Disabling the Diagnostics Tracking Service
                        Stop-Service "DiagTrack"
                        Set-Service "DiagTrack" -StartupType Disabled
                        $lb_log.text = "Telemetry has been disabled!"
                            
                        

                    } -name "jobdistelemetry"

                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }
                if ($selected.Contains("Desabilitar Cortana")) {

                    Start-Job -ScriptBlock {

                        $ErrorActionPreference = 'SilentlyContinue'
                        $lb_log.text = "Disabling Cortana..."
                        $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
                        $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
                        $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
                        If (!(Test-Path $Cortana1)) {
                            New-Item $Cortana1
                        }
                        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
                        If (!(Test-Path $Cortana2)) {
                            New-Item $Cortana2
                        }
                        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
                        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
                        If (!(Test-Path $Cortana3)) {
                            New-Item $Cortana3
                        }
                        Set-ItemProperty $Cortana3 HarvestContacts -Value 0
                        $lb_log.text = "Cortana has been disabled..."
                        

                    } -Name "jobdiscortana"

                    $restart = $true
                    $cont ++
                    $ProgressBar.value = ($cont / $cont_max) * 100
                    $lb_percent.Text = (($cont / $cont_max) * 100), "%"
                    
                }

                # Condição depois de rodar tudo 
                if ($selected) {

                    $cb_list_function.SetItemChecked(0, 0)
                    $cb_list_function.SetItemChecked(1, 0)
                    $cb_list_function.SetItemChecked(2, 0)
                    $cb_list_function.SetItemChecked(3, 0)
                    $cb_list_function.SetItemChecked(4, 0)
                    $cb_list_function.SetItemChecked(5, 0)
                    $cb_list_function.SetItemChecked(6, 0)
                    $cb_list_function.SetItemChecked(7, 0)
                    $cb_list_function.SetItemChecked(8, 0)
                    $cb_list_function.SetItemChecked(9, 0)
                    $cb_list_function.SetItemChecked(10, 0)

                    if ($restart) {
                        $result = [System.Windows.Forms.MessageBox]::Show('Para que todas as mudanças sejam aplicadas, o computador deve ser reiniciado. Deseja reiniciar agora?' , "Execução finalizada" , 4)
                        if ($result -eq 'Yes') {
                            shutdown -r -t 0 -f
                        }
                        else { 
                            $suporte_GUI.Close()
                        }
                    }

                }
                
            })
        $start_button.Add_MouseEnter({
                $start_button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
                $start_button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
            })
        $start_button.Add_MouseLeave({
                $start_button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
                $start_button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFF")
            })


        $suporte_GUI.Refresh()
        [void]$suporte_GUI.ShowDialog()
        
    }
    Form
}
    
main_form