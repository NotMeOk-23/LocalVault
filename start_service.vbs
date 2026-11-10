Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Detect pythonw.exe path dynamically
pythonwPath = "pythonw.exe"
userProfile = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")
candidatePath = userProfile & "\Programs\Python\Python313\pythonw.exe"
If fso.FileExists(candidatePath) Then
    pythonwPath = candidatePath
End If

' Use WMI Win32_Process Create to detach from parent process tree completely
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set objProcess = objWMIService.Get("Win32_Process")

cmdLine = """" & pythonwPath & """ """ & scriptDir & "\core\tray_service.py"""
errReturn = objProcess.Create(cmdLine, scriptDir, Null, intProcessID)
