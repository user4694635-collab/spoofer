FOR /L %%N IN (1,1,50) DO ECHO. Nothing >Nul 2>&1

CLS & CALL:Embed
FOR /F "tokens=2" %%I IN ('Whoami /user /fo table /nh') DO SET SID=%%I

FOR %%X IN (
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
) DO (
    REG DELETE %%X /F > %TEMP%\Output
    if "%ErrorLevel%"=="0" ( Type %TEMP%\Output )
)

ECHO. & ECHO. Deleting Windows Traces ...
FOR %%X IN (
    "%SystemDrive%\$Recycle.Bin", "%SystemDrive%\MSOCache", "%SystemDrive%\Recovery",
    "%AppData%\Microsoft\Windows\Recent", "%LocalAppData%\Temp", "%AppData%\Temp",
    "%WinDir%\CbsTemp", "%WinDir%\Temp", "%WinDir%\Logs", "%WinDir%\Prefetch",
    "%ProgramData%\Microsoft\Windows\WER", "%ProgramData%\Package Cache",
    "%LocalAppData%\Microsoft\Feeds Cache", "%LocalAppData%\FontCache",
    "%ProgramFiles%\Internet Explorer",
) DO (
    IF EXIST %%X (
        Takeown /F %%X /A >Nul 2>&1 & Icacls %%X /Grant %UserName%:F >Nul 2>&1
        ATTRIB -H -R -S -A /S /D %%X >Nul 2>&1 & Rmdir /S /Q %%X
    )
)
FOR /F "tokens=2 delims==" %%I IN ('wmic logicaldisk get caption /value') DO (
    Set "SVI=System Volume Information"
    Takeown /F "%%J:\%SVI%" /A >Nul 2>&1 & Icacls "%%J:\%SVI%" /Grant %UserName%:F >Nul 2>&1
    Del /F /S /Q /A:H /A:A /A:S "%%J:\%SVI%\*" & Rmdir /S /Q "%%J:\%SVI%"
    FOR /F "tokens=1 delims=:" %%J IN ("%%I") DO (
        Takeown /F "%%J:" /A >Nul 2>&1 & Icacls "%%J:" /Grant %UserName%:F >Nul 2>&1
        FOR %%X IN (pf dmp old tmp log bk mdmp gid fts) DO (
            Del /F /S /Q /A:H /A:S /A:A %%J:\*.%%X > %TEMP%\Output
            if "%ErrorLevel%"=="0" ( Type %TEMP%\Output )
        )
    )
)

ECHO. & ECHO. Deleting Network Traces ...
ARP -A & ARP -D & ARP -D * & NETSH INTERFACE IP DELETE ARPCACHE & ARP -A
NBTSTAT -R & NBTSTAT -R & NETSH WINSOCK RESET & NETSH ADVFIREWALL RESET
NETSH INTERFACE IP RESET & NETSH INTERFACE TCP RESET & NETSH INTERFACE IPV4 RESET
NETSH INTERFACE IPV6 RESET & NETSH INTERFACE RESET ALL

ECHO. & ECHO. Deleting Regedit Traces Paths ...
FOR %%X IN (
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage",
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
    "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\%SID%",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
    "HKCR\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\UFH\SHC",
    "HKLM\SYSTEM\ControlSet001\Services\EventLog\State",
    "HKLM\SOFTWARE\Microsoft\DirectInput\Compatibility",
    "HKLM\SOFTWARE\Microsoft\Dfrg\Statistics",
    "HKCU\Software\Microsoft\Direct3D",
    "HKCU\Software\Classes\Interface",
    "HKLM\SYSTEM\MountedDevices"
) DO (
    REG DELETE %%X /VA /F > %TEMP%\Output
    if "%ErrorLevel%"=="0" ( Type %TEMP%\Output )
)

FOR %%X IN (
    "HKLM\SYSTEM\CurrentControlSet\Services\mssmbios", "HKLM\HARDWARE\DESCRIPTION\System",
    "HKLM\SYSTEM\HardwareConfig", "HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation"
) DO (
    REG DELETE %%X /F > %TEMP%\Output
    if "%ErrorLevel%"=="0" ( Type %TEMP%\Output )
)

ECHO. & ECHO. Spoofing Regedit Values ...
Set NewComputerName=DESKTOP-%Random%
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d "!Serial!" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid /t REG_SZ /d "!Serial!" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUID /t REG_SZ /d "ffffffff-ffff-ffff-ffff-ffffffffffff" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v InstallDate /t REG_SZ /d "!Random!!Random!" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d "%NewComputerName%" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d "%NewComputerName%" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v SusClientId /t REG_SZ /d "{!Serial!}" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v Hostname /t REG_SZ /d "%NewComputerName%" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v NV" "Hostname /t REG_SZ /d "%NewComputerName%" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d "%NewComputerName%" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d "%NewComputerName%" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v GUID /t REG_SZ /d "{!Serial!}" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v HwProfileGuid /t REG_SZ /d "{!Serial!}" /F
CALL:GenUUID & REG ADD HKLM\System\CurrentControlSet\Control\SystemInformation /v ComputerHardwareIds /t REG_SZ /d "{!Serial!}" /F
CALL:GenUUID & REG ADD HKLM\System\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d "{!Serial!}" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v UserModeDriverGUID /t REG_SZ /d "{!Serial!}" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\NVIDIA" "Corporation\Global\CoProcManager /v ChipsetMatchID /t REG_SZ /d "!Serial!" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\NVIDIA" "Corporation\Global /v persistenceidentifier /t REG_SZ /d "!Serial!" /F
CALL:GenUUID & REG ADD HKLM\SOFTWARE\NVIDIA" "Corporation\Global /v clientuuid /t REG_SZ /d "!Serial!" /F
CALL:GenUUID & REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d "{!Serial!}" /F
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 0 /F
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI /v WindowsAIKHash /t REG_BINARY /d "!Random!!Random!!Random!!Random!!Random!!Random!!Random!!Random!" /F
CALL POWERSHELL Rename-LocalUser -Name "%UserName%" -NewName "User-!Random:~0,5!" >NUL 2>&1
CALL POWERSHELL Rename-Computer -NewName "%NewComputerName%" >NUL 2>&1

ECHO. & ECHO. Deleting Events ...
FOR /F "tokens=*" %%G IN ('wevtutil.exe el') DO CALL Wevtutil.exe cl %%G >Nul 2>&1 & Echo. Deleting - %%G
POWERSHELL -C "Disable-MMAgent -mc"

Taskkill /F /IM WmiPrvSE.exe /T >Nul 2>&1

CLS & CALL:Embed
ECHO. Cleaning process finished! Raccomand Reboot your PC, create a fresh game account, and back to playing.
ECHO. [WARN]: Windows don't work correcty without reboot.
ECHO. Press Any Key To Exit ... & PAUSE >Nul 2>&1 & Exit & EXIT

:GenUUID
    set "uuid=" & set "chars=aAbBcCdDeEfFgG023456789"
    for /L %%i in (1,1,64) do (
        set /a "index=!random! %% 36"
        for %%j in (!index!) do set "uuid=!uuid!!chars:~%%j,1!"
    ) & set "Serial=!uuid:~0,8!-!uuid:~8,4!-!uuid:~12,4!-!uuid:~16,4!-!uuid:~20,12!"
GOTO :EOF

:Embed
    ECHO. ^+---------------------------------------------------------------------------^+
    ECHO. ^|            Deep Cleaner. All Rights Reserved @agre.ud agreement.          ^|
    ECHO. ^|        Last Traces Update At 05/02/2026 Current Data Is %DATE%.       ^|
    ECHO. ^+---------------------------------------------------------------------------^+
    ECHO.
GOTO:EOF
