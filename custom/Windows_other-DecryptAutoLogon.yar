rule OTHER_DECRYPTAUTOLOGON
{
    meta:
        description = "used to decrypt autologn creds for windows"
        author = "Adam"
        date = "3/9/2026"
        confidence = "high"
        scope = ".exe file"
    
    strings:
        $thing2 = "mscoree.dll" ascii
        $thing3 = "LsaRetrievePrivateData" ascii
        $thing4 = "LsaOpenPolicy" ascii
        $thing5 = "LsaNtStatusToWinError" ascii

        $a1 = "PtrToStringUni" ascii
        $a2 = "AllocHGlobal" ascii
        $a3 = "FreeHGlobal" ascii

    condition:
        (2 of ($thing*)) and (1 of ($a*))         
}