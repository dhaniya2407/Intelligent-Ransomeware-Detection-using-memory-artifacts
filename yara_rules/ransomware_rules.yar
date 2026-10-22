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


rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Detects attempts to delete shadow copies or inhibit system recovery"
        author = "ForensiRansom AI"
        severity = "CRITICAL"
        mitre_technique = "T1490"

    strings:
        $vssadmin1 = "vssadmin delete shadows" nocase
        $vssadmin2 = "vssadmin.exe delete shadows" nocase
        $wmic1 = "wmic shadowcopy delete" nocase
        $wmic2 = "shadowcopy delete" nocase
        $wbadmin1 = "wbadmin delete catalog" nocase
        $bcdedit1 = "bcdedit" nocase
        $bcdedit2 = "recoveryenabled No" nocase
        $bcdedit3 = "bootstatuspolicy ignoreallfailures" nocase

    condition:
        any of ($vssadmin*) or any of ($wmic*) or $wbadmin1 or ($bcdedit1 and ($bcdedit2 or $bcdedit3))
}


rule Ransomware_Note_Artifacts
{
    meta:
        description = "Detects common ransomware note strings and extortion markers"
        author = "ForensiRansom AI"
        severity = "HIGH"
        mitre_technique = "T1486"

    strings:
        $note1 = "your files have been encrypted" nocase
        $note2 = "all your documents, photos, databases" nocase
        $note3 = "README_FOR_DECRYPT" nocase
        $note4 = "HOW_TO_RECOVER_FILES" nocase
        $note5 = "DECRYPT_FILES" nocase
        $onion1 = ".onion" nocase
        $tor1 = "tor browser" nocase
        $pay1 = "bitcoin" nocase
        $pay2 = "monero" nocase

    condition:
        any of ($note*) or ($onion1 and $tor1) or (any of ($pay*) and any of ($note*))
}


rule Ransomware_Process_Termination
{
    meta:
        description = "Detects force termination of backup, database, or security processes"
        author = "ForensiRansom AI"
        severity = "MEDIUM"
        mitre_technique = "T1489"

    strings:
        $kill1 = "taskkill /f /im" nocase
        $kill2 = "taskkill.exe /f /im" nocase
        $stop1 = "net stop" nocase
        $stop2 = "sc stop" nocase

    condition:
        any of them
}
