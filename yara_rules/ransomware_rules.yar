rule Suspicious_PowerShell_Execution
{
    meta:
        description = "Detects PowerShell execution indicators"
        author = "ForensiRansom AI"
        severity = "MEDIUM"

    strings:
        $powershell1 = "powershell.exe" nocase
        $powershell2 = "powershell " nocase
        $encoded1 = "-EncodedCommand" nocase
        $encoded2 = "-enc " nocase

    condition:
        any of ($powershell*) or any of ($encoded*)
}


rule Suspicious_Command_Execution
{
    meta:
        description = "Detects suspicious command execution tools"
        author = "ForensiRansom AI"
        severity = "LOW"

    strings:
        $cmd = "cmd.exe" nocase
        $wscript = "wscript.exe" nocase
        $cscript = "cscript.exe" nocase
        $mshta = "mshta.exe" nocase
        $rundll32 = "rundll32.exe" nocase

    condition:
        any of them
}