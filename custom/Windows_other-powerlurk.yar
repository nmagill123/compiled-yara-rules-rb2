rule OTHER_POWERLURK
{
    meta:
        description = "this is the main tool, used to setup malicious WMI events for persistence"
        author = "Adam"
        date = "3/9/2026"
        confidence = "high"
        scope = ".ps1 file"
    
    strings:
        $fun1 = "Register-MaliciousWmiEvent" ascii
        $fun2 = "Add-TemplateLurker" ascii
        $fun3 = "Remove-TemplateLurker" ascii

        $wmi1 = "root/subscription" ascii
        $wmi2 = "__FilterToConsumerBinding" ascii
        $wmi3 = "CommandLineEventConsumer" ascii
        $wmi4 = "ActiveScriptEventConsumer" ascii

        $payload1 = "FromBase64String" ascii
        $payload2 = "Invoke-Expression" ascii
        $payload3 = "ToBase64String" ascii
        
    condition:
        (1 of ($fun*)) or 
        (
            (2 of ($wmi*)) and (1 of ($payload*))
        )
}

rule OTHER_KEETHIEFLURKER
{
    meta:
        description = "creates permanent WMI event that will execute KeeThief https://github.com/adaptivethreat/KeeThief"
        author = "Adam"
        date = "3/9/2026"
        confidence = "high"
        scope = ".ps1 file"
    
    strings:
        $fun1 = "$Payload" ascii
        $fun2 = "Custom WMI Class Win32_" ascii
        $fun3 = "Remove-KeeThiefLurker -EventName"
        $fun4 = "Cleanup Command" ascii

        $cmd1 = "Powershell.exe -NoP -C Start-Sleep -Seconds" ascii
        $cmd2 = "$(Get-ItemProperty -Path `$RegistryPath -Name $PayloadValueName).$PayloadValueName" ascii
        $cmd3 = "$EncodedOutput = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$OutputString))" ascii
        $cmd4 = "$Output = Invoke-Expression -Command `$([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$Payload)))" ascii
        $cmd5 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($(Get-WmiObject -Namespace root\software win32_WindowsUpdate -List).Properties['Output'].value))"


        
    condition:
        (1 of ($fun*)) and (1 of ($cmd*)) 
        or (2 of ($cmd*))
}