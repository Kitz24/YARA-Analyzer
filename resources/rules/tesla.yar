import "pe"

rule AgentTesla_Suspicious_Behaviors
{
    meta:
        author      = "Analyst"
        description = "Detects Agent Tesla via NSIS stub + dynamic API, privilege, registry & COM calls"
        date        = "2025-04-28"

    strings:
        /* NSIS self‐extractor stub */
        $nsis_xml      = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        $nsis_marker   = "NullsoftInstR"

        /* Dynamic resolution */
        $gpa           = "GetProcAddress"
        $llex          = "LoadLibraryExW"

        /* Privilege escalation */
        $adjpriv       = "AdjustTokenPrivileges"
        $lookup        = "LookupPrivilegeValueW"
        $setsec        = "SetFileSecurityW"

        /* Registry persistence */
        $reg_open      = "RegOpenKeyExW"
        $reg_set       = "RegSetValueExW"
        $reg_create    = "RegCreateKeyExW"

        /* COM init */
        $cocreate      = "CoCreateInstance"
        $oleinit       = "OleInitialize"

    condition:
        pe.is_pe and

        /* NSIS stub present */
        any of ($nsis_*) and

        /* dynamic API resolving */
        any of ($gpa, $llex) and

        /* privilege escalation usage */
        any of ($adjpriv, $lookup, $setsec) and

        /* registry‐based persistence */
        any of ($reg_open, $reg_set, $reg_create) and

        /* COM automation */
        all of ($cocreate, $oleinit)
}
