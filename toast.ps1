<#
.SYNOPSIS
    A simple Toast notification script.
.DESCRIPTION
    A simple Toast notification script that can be run as the user or as system and redirected to the user.
.EXAMPLE
    Basic example
    PS C:\> .\toast.ps1 

    Toast with all options
    PS C:\> .\toast.ps1 -title "Title" -message "Message goes here" -heroImage "https://picsum.photos/364/180?image=1043" -inlineImage "https://picsum.photos/364/180?image=1043" -logo "C:\Program Files\Toast\Images\ToastLogoImageWindows.jpg" -attribution "From IT" -protocolButtonTxt "Click Me!" -protocolButtonlink "https://example.com" -dismissButton
    
    Example for calling from within another script

    ---Start Script Example---
    $filePath = "C:\Program Files\Toast\toast.ps1"

    $params = @{
        title = "Hello"
        message = "This is a toast message"
        heroImage = "https://picsum.photos/364/180?image=1043"
        logo = "C:\Program Files\Toast\Images\ToastHeroImageDefault.jpg"
    }

    & $filePath @params 
    ---End Script Example---

.INPUTS
    -title 
        The title for the toast notification

    -message
        The main message for the toast notification.
    
    -heroImage [headerImage]
        Optional 'Hero' image
    
    -inlineImage [image, bodyImage, mainImage]
        Optional inline\body\main image
    
    -logo [appOverrideLogo]
        Optional 'Logo' image to be displayed next to the message
    
    -attribution
        Optional attribution text
    
    -protocolButton [protocolButtonLink]
        Optional protocol link button. Make sure you specify the protocol, such as 'https://' before your link!

    -protocolButtonText
        Optional override for the default protocol link Button text. 
        Try to keep this text short, there is a limit of around 36 characters. Remember, multiple buttons have less text space!

    -dismiss [dismissButton]
        Optional dismiss button

    -snoooze [snoozeButton]
        Optional snooze button using the system default snooze time

    -snoozeOptions [snoozeButtonOptions]
        Optional options for the user to select how long to snooze for. 
        These must be specified in the following format "ID:Text" where ID is the length in minutes to snooze for and each item is seperated by a comma.
        For example, to add 2 options to snooze for 1 minute and 1 hour, use "1:1 minute,60:1 hour"
    
    -snoozeDefault [snoozeOptionsDefault]
        Optional default snooze option to select. If not specified the first option will be automatically selected.
        Specify the 'snoozeButtonOptions' ID to make that option the default selection.
        For example, based on the options "1:1 minute,60:1 hour", setting '1' would select the first option and '60' would select the second option

    -snoozeOptionsText [snoozeButtonText]
        Optional text to display above the custom snooze options

.OUTPUTS
    A Toast notification

.NOTES
    Thank you to the following projects for providing inspiration and some of the code 

    https://github.com/Windos/BurntToast
    https://github.com/imabdk/Toast-Notification-Script

    Version History
    1.0.0 - Initial release

    1.1.0 - Snooze Added
        Added the ability to add a snooze button with custom times and text.
        The snooze and dismiss buttons order is dependent on the order in which they are specified as parameters.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$title = "Title",
    [Parameter(Mandatory = $false)]
    [string]$message = "Message",
    [Parameter(Mandatory = $false)]
    [Alias("appOverrideLogo")]
    [string]$logo,
    [Parameter(Mandatory = $false)]
    [string]$attribution,
    [Parameter(Mandatory = $false)]
    [Alias("headerImage")]
    [string]$heroImage,
    [Parameter(Mandatory = $false)]
    [Alias("image", "bodyImage","mainImage")]
    [string]$inlineImage,
    [Parameter(Mandatory = $false)]
    [Alias("protocolButton")]
    [string]$protocolButtonLink,
    [Parameter(Mandatory = $false)]
    [string]$protocolButtonText= "Click me!",
    [Parameter(Mandatory = $false)]
    [Alias("dismissButton")]
    [switch]$dismiss,
    [Parameter(Mandatory = $false)]
    [Alias("snoozeButton")]
    [switch]$snooze,
    [Parameter(Mandatory = $false)]
    [Alias("snoozeButtonOptions")]
    [string]$snoozeOptions,
    [Parameter(Mandatory = $false)]
    [Alias("snoozeOptionsDefault")]
    [string]$snoozeDefault = -1,
    [Parameter(Mandatory = $false)]
    [string]$snoozeOptionsText = $null

)

function Write-Log() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = "$env:TEMP\toastNotification.log",
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]$Level = "Info",
        [Parameter(Mandatory = $false)]
        [bool]$LogToFile = $false
    )
    Begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process {
        if (Test-Path $Path) {
            $LogSize = (Get-Item -Path $Path).Length / 1MB
            $MaxLogSize = 5
        }
        # Check for file size of the log. If greater than 5MB, it will create a new one and delete the old.
        if ((Test-Path $Path) -AND $LogSize -gt $MaxLogSize) {
            Write-Error "Log file $Path already exists and file exceeds maximum file size. Deleting the log and starting afresh."
            Remove-Item $Path -Force
            $null = New-Item $Path -Force -ItemType File
        }
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (-NOT(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $null = New-Item $Path -Force -ItemType File
        }
        else {
            # Nothing to see here yet.
        }
        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
            }
        }
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}

function Test-NTSystem() {  
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.IsSystem -eq $true) {
        Write-Log -Message "Script is initially running in SYSTEM context. Please be careful, that this has limitations and may not work!"
        $true  
    }
    elseif ($currentUser.IsSystem -eq $false) {
        Write-Log -Message "Script is initially running in USER context"
        $false
    }
}

#Main Script
Write-Log -Message "------------- TOAST SCRIPT CALLED -------------"

if (Test-NTSystem) {
    try {
        [String]$Script = @'
param(
    [Parameter()]
    [string]$file,
    [Parameter()]
    [string]$argument
    
)

$Source = @"
using System;
using System.Runtime.InteropServices;

namespace Runasuser
{
public static class ProcessExtensions
{
#region Win32 Constants

private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
private const int CREATE_NO_WINDOW = 0x08000000;

private const int CREATE_NEW_CONSOLE = 0x00000010;

private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

#endregion

#region DllImports

[DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
private static extern bool CreateProcessAsUser(
IntPtr hToken,
String lpApplicationName,
String lpCommandLine,
IntPtr lpProcessAttributes,
IntPtr lpThreadAttributes,
bool bInheritHandle,
uint dwCreationFlags,
IntPtr lpEnvironment,
String lpCurrentDirectory,
ref STARTUPINFO lpStartupInfo,
out PROCESS_INFORMATION lpProcessInformation);

[DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
private static extern bool DuplicateTokenEx(
IntPtr ExistingTokenHandle,
uint dwDesiredAccess,
IntPtr lpThreadAttributes,
int TokenType,
int ImpersonationLevel,
ref IntPtr DuplicateTokenHandle);

[DllImport("userenv.dll", SetLastError = true)]
private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

[DllImport("userenv.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool CloseHandle(IntPtr hSnapshot);

[DllImport("kernel32.dll")]
private static extern uint WTSGetActiveConsoleSessionId();

[DllImport("Wtsapi32.dll")]
private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

[DllImport("wtsapi32.dll", SetLastError = true)]
private static extern int WTSEnumerateSessions(
IntPtr hServer,
int Reserved,
int Version,
ref IntPtr ppSessionInfo,
ref int pCount);

#endregion

#region Win32 Structs

private enum SW
{
SW_HIDE = 0,
SW_SHOWNORMAL = 1,
SW_NORMAL = 1,
SW_SHOWMINIMIZED = 2,
SW_SHOWMAXIMIZED = 3,
SW_MAXIMIZE = 3,
SW_SHOWNOACTIVATE = 4,
SW_SHOW = 5,
SW_MINIMIZE = 6,
SW_SHOWMINNOACTIVE = 7,
SW_SHOWNA = 8,
SW_RESTORE = 9,
SW_SHOWDEFAULT = 10,
SW_MAX = 10
}

private enum WTS_CONNECTSTATE_CLASS
{
WTSActive,
WTSConnected,
WTSConnectQuery,
WTSShadow,
WTSDisconnected,
WTSIdle,
WTSListen,
WTSReset,
WTSDown,
WTSInit
}

[StructLayout(LayoutKind.Sequential)]
private struct PROCESS_INFORMATION
{
public IntPtr hProcess;
public IntPtr hThread;
public uint dwProcessId;
public uint dwThreadId;
}

private enum SECURITY_IMPERSONATION_LEVEL
{
SecurityAnonymous = 0,
SecurityIdentification = 1,
SecurityImpersonation = 2,
SecurityDelegation = 3,
}

[StructLayout(LayoutKind.Sequential)]
private struct STARTUPINFO
{
public int cb;
public String lpReserved;
public String lpDesktop;
public String lpTitle;
public uint dwX;
public uint dwY;
public uint dwXSize;
public uint dwYSize;
public uint dwXCountChars;
public uint dwYCountChars;
public uint dwFillAttribute;
public uint dwFlags;
public short wShowWindow;
public short cbReserved2;
public IntPtr lpReserved2;
public IntPtr hStdInput;
public IntPtr hStdOutput;
public IntPtr hStdError;
}

private enum TOKEN_TYPE
{
TokenPrimary = 1,
TokenImpersonation = 2
}

[StructLayout(LayoutKind.Sequential)]
private struct WTS_SESSION_INFO
{
public readonly UInt32 SessionID;

[MarshalAs(UnmanagedType.LPStr)]
public readonly String pWinStationName;

public readonly WTS_CONNECTSTATE_CLASS State;
}

#endregion

// Gets the user token from the currently active session
private static bool GetSessionUserToken(ref IntPtr phUserToken)
{
var bResult = false;
var hImpersonationToken = IntPtr.Zero;
var activeSessionId = INVALID_SESSION_ID;
var pSessionInfo = IntPtr.Zero;
var sessionCount = 0;

// Get a handle to the user access token for the current active session.
if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
{
    var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
    var current = pSessionInfo;

    for (var i = 0; i < sessionCount; i++)
    {
        var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
        current += arrayElementSize;

        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
        {
            activeSessionId = si.SessionID;
        }
    }
}

// If enumerating did not work, fall back to the old method
if (activeSessionId == INVALID_SESSION_ID)
{
    activeSessionId = WTSGetActiveConsoleSessionId();
}

if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
{
    // Convert the impersonation token to a primary token
    bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
        ref phUserToken);

    CloseHandle(hImpersonationToken);
}

return bResult;
}

public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
{
var hUserToken = IntPtr.Zero;
var startInfo = new STARTUPINFO();
var procInfo = new PROCESS_INFORMATION();
var pEnv = IntPtr.Zero;
int iResultOfCreateProcessAsUser;

startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

try
{
    if (!GetSessionUserToken(ref hUserToken))
    {
        throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
    }

    uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
    startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
    startInfo.lpDesktop = "winsta0\\default";

    if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
    {
        throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
    }

    if (!CreateProcessAsUser(hUserToken,
        appPath, // Application Name
        cmdLine, // Command Line
        IntPtr.Zero,
        IntPtr.Zero,
        false,
        dwCreationFlags,
        pEnv,
        workDir, // Working directory
        ref startInfo,
        out procInfo))
    {
        iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
        throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.  Error Code -" + iResultOfCreateProcessAsUser);
    }

    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
}
finally
{
    CloseHandle(hUserToken);
    if (pEnv != IntPtr.Zero)
    {
        DestroyEnvironmentBlock(pEnv);
    }
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
}

return true;
}

}
}
"@

# Load the custom type if not already loaded
if (-not ([System.Management.Automation.PSTypeName]'Runasuser.ProcessExtensions').Type)
{
    Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $Source -Language CSharp -ErrorAction silentlycontinue
}

# Run PS as user to display the message box
[Runasuser.ProcessExtensions]::StartProcessAsCurrentUser("$env:windir\System32\WScript.exe", "- `"$file`" `"$argument`"") | Out-Null
'@

        [String]$hidePSVBS = @'
set shell = CreateObject("WScript.Shell")
newArgument = (Replace(WScript.Arguments(0),"'",""""))

'get all arguments. If first contains .vbs ignore it else loop through all arguments and put them in one big argument.
Set objArgs = Wscript.Arguments

newArgument = ""
For i = 0 to objArgs.Count - 1
  if i = 0 then
    if InStr(objArgs(i),".vbs") then
      'Do nothing
    else
      newArgument = objArgs(i)
    end if
  else
    newArgument = newArgument + " " + objArgs(i)
  end if
Next

newArgument = (Replace(WScript.Arguments(0),"'",""""))

command = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File " & newArgument

shell.Run command,0	
'@ 

        $hidePSVBSPath = "$PSScriptRoot\hidePS.vbs"
        $scriptPath = "$env:TEMP\runAsUser.ps1"
        
        if (-NOT[string]::IsNullOrEmpty($Script)) {
            Write-Log -Message "Creating 'runAsUser.ps1'"
            Out-File -FilePath $scriptPath -InputObject $Script -Encoding ASCII -Force
        }

        #Create the VB Script that hides the PowerShell window when we run as the user. Note: This is created under the same location as the main script as it has to be accessible for both the system user and end user
        if (-NOT[string]::IsNullOrEmpty($hidePSVBS)) {
            Write-Log -Message "Creating 'hidePS.vbs'"
            Out-File -FilePath $hidePSVBSPath -InputObject $hidePSVBS -Encoding ASCII -Force
        }

        $argumentList = "-file ""$hidePSVBSPath"" -argument ""'$PSScriptRoot\toast.ps1' -Title '$title' -Message '$message'"

        if ($logo) {
            $argumentList = $argumentList + " -logo '$logo'"
        }

        if ($heroImage) {
            $argumentList = $argumentList + " -heroImage '$heroImage'"
        }
        
        if ($attribution) {
            $argumentList = $argumentList + " -attribution '$attribution'"
        }
        
        if ($dismissButton) {
            $argumentList = $argumentList + " -dismissButton $dismissButton"
        }
        $argumentList = $argumentList + "`""
        Write-Log -Message "Attempting to relaunch the script as the logged on user"
        Invoke-Expression "$scriptPath $argumentList"
    } 
    catch {
        Write-Log -Level Error "Failed to create the .ps1 script for $Type. Show notification if run under SYSTEM might not work"
        $ErrorMessage = $_.Exception.Message
        Write-Log -Level Error -Message "Error message: $ErrorMessage"
    }
    Exit
}

if ($IsWindows) {
    $paths = "$PSScriptRoot\lib\Microsoft.Toolkit.Uwp.Notifications\net5.0-windows10.0.17763\*.dll", "$PSScriptRoot\lib\Microsoft.Windows.SDK.NET\*.dll"

    $Library = @( Get-ChildItem -Path $Paths -Recurse -ErrorAction SilentlyContinue )

    # Add one class from each expected DLL here:
    $LibraryMap = @{
        'Microsoft.Toolkit.Uwp.Notifications.dll' = 'Microsoft.Toolkit.Uwp.Notifications.ToastContent'
    }

    foreach ($Type in $Library) {
        try {
            if (-not ($LibraryMap[$Type.Name] -as [type])) {
                Add-Type -Path $Type.FullName -ErrorAction Stop
            }
        }
        catch {
            Write-Error -Message "Failed to load library $($Type.FullName): $_"
        }
    }
}
else {
    Add-Type -Path "$PSScriptRoot\lib\Microsoft.Toolkit.Uwp.Notifications\net461\Microsoft.Toolkit.Uwp.Notifications.dll"
}

try {
    #Tidy up the incomming variables. Note ## is replaced with a quote
    $title = $title.Replace("'", "")
    $title = $title.Replace('##', '"')
    $message = $message.Replace("'", "")
    $message = $message.Replace('##', '"')
    $heroImage = $heroImage.Replace("'", "")
    $protocolButtonText = $protocolButtonText.Replace("'", "")
    $snoozeOptionsText = $snoozeOptionsText.Replace("'", "")
  
    $invocationLine = $MyInvocation.Line.toLower()
    $invocationLine = $invocationLine.Replace("snoozebutton","snooze")
    $invocationLine = $invocationLine.Replace("snoozebuttonoptions","snoozeoptions")
    $invocationLine = $invocationLine.Replace("dismissbutton","dismiss")

    $invocationLine

    $invocationLine.IndexOf("-snooze")
    $invocationLine.IndexOf("-snoozeoptions")
    $invocationLine.IndexOf("-dismiss")

    if((35 -le 26) -or (43 -le 26)){
    Write-Host "true"
    }
    else{
    Write-Host "false"
    }

    if((($invocationLine.IndexOf("-snooze")) -le ($invocationLine.IndexOf("-dismiss"))) -or (($invocationLine.IndexOf("-snoozeoptions")) -le ($invocationLine.IndexOf("-dismiss")))) {
    #if(($invocationLine.IndexOf("-snooze") -or $invocationLine.IndexOf("-snoozeoptions")) -le ($invocationLine.IndexOf("-dismiss"))) {
        $snoozeButtonFirst = $true
    }
    else{
        $snoozeButtonFirst = $false
    }

    $toast = [Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder]::new()

    #  This can be considered to be the "title" text on line #1.
    #  A minimum of 1 line of text is required

    Write-Log -Message "Adding the title: '$title'"
    $toast.AddText($title) >> $null

    Write-Log -Message "Adding the main messasge: '$message'"
    $toast.AddText($message) >> $null

    if ($logo) {
        Write-Log -Message "Adding applicaiton logo; '$logo'"
        $toast.AddAppLogoOverride($logo, 'None') >> $null
    }

    if ($heroImage) {

        if ($heroImage.StartsWith("https://") -or $heroImage.StartsWith("http://")) {
            $newHeroImage = "$env:TEMP\heroImage.jpg"
            Invoke-WebRequest -Uri $heroImage -OutFile $newHeroImage
            Write-Log -Message "Adding remote hero image: '$heroImage'"
            $toast.AddHeroImage($newHeroImage) >> $null
        
        }
        else {
            Write-Log -Message "Adding local hero image: '$heroImage'"
            $toast.AddHeroImage($heroImage) >> $null
        }
    }

    if ($inlineImage) {

        if ($inlineImage.StartsWith("https://") -or $inlineImage.StartsWith("http://")) {
            $newInlineImage = "$env:TEMP\inlineImage.jpg"
            Invoke-WebRequest -Uri $inlineImage -OutFile $newInlineImage
            Write-Log -Message "Adding remote inline image: '$inlineImage'"
            $toast.AddInlineImage($newInlineImage) >> $null
        
        }
        else {
            Write-Log -Message "Adding local inline image: '$inlineImage'"
            $toast.AddInlineImage($inlineImage) >> $null
        }
    }

    if ($attribution) {
        Write-Log -Message "Adding attribution: '$attribution'"
        $toast.AddAttributionText($attribution) >> $null
    }

    if ($protocolButtonLink) {
        Write-Log -Message "Adding a protocol button to '$protocolButtonLink' with text '$protocolButtonText'"
        $toast.AddButton($protocolButtonText, 'Protocol', $protocolButtonLink) >> $null
    }

    if ($dismiss -and !$snoozeButtonFirst) {
        Write-Log -Message "Adding a dismiss button"
        $toast.AddButton([Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new()) >> $null
    }



    #$toast.SetToastScenario("Reminder")


    if($snoozeButton -or $snoozeOptions){

        if($snoozeOptions){

            $choicesArray = $snoozeOptions.Split(",")
            $choices2DArray = New-Object 'object[,]' $choicesArray.Length,2
            $choices = @()

            #Build the 2D array from the options sent and look for a valid default to select
            for($i=0; $i -lt $choicesArray.Length; $i++){
                $pos = $choicesArray[$i].IndexOf(":")
                $choices2DArray[$i,0] += $choicesArray[$i].Substring(0, $pos)
                $choices2DArray[$i,1] += $choicesArray[$i].Substring($pos+1, $choicesArray[$i].Length -$pos -1)
                $choices += [ValueTuple[string, string]]::new(($choices2DArray[$i,0]),($choices2DArray[$i,1]))
                if($snoozeDefault -eq $choices2DArray[$i,0]){
                    $snoozeDefaultTemp = $choices2DArray[$i,0]
                }
            }

            if($snoozeDefault -ne $snoozeDefaultTemp){
                $snoozeDefault = $choices2DArray[0,0]
            }

            $toast.AddComboBox("dropdown",$snoozeOptionsText ,$snoozeDefault, $Choices) >> $null

            $toastSnooze = [Microsoft.Toolkit.Uwp.Notifications.ToastButtonSnooze]::new()
            $toastSnooze.SelectionBoxId = "dropdown"

            Write-Log -Message "Adding a custom snooze button ($snoozeOptions), option ID $snoozeDefault selected"
            $toast.AddButton($toastSnooze) >> $null
        }
        else {
            Write-Log -Message "Adding a default snooze button"
            $toast.AddButton([Microsoft.Toolkit.Uwp.Notifications.ToastButtonSnooze]::new()) >> $null
        }
    
        
    }

    if ($dismiss -and $snoozeButtonFirst) {
        Write-Log -Message "Adding a dismiss button"
        $toast.AddButton([Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new()) >> $null
    }

    #  Make the notification appear on the desktop.
    Write-Log -Message "Running the 'Show' command"
    $toast.Show()

    if (Test-Path -Path "$PSScriptRoot\hidePS.vbs" -PathType Leaf){
        Write-Log -Message "Found $PSScriptRoot\hidePS.vbs, deleting"
        Remove-Item "$PSScriptRoot\hidePS.vbs"
    }
}
catch {
    Write-Log -Level Error "Failed to create create the toast notification"
    $ErrorMessage = $_.Exception.Message
    Write-Log -Level Error -Message "Error message: $ErrorMessage"
}


Write-Log -Message "------------- TOAST SCRIPT ENDED -------------"