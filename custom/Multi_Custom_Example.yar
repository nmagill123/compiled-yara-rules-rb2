/*
   YARA Rule: Multi_Custom_Example
   
   This is an example custom YARA rule that demonstrates proper structure.
   Replace this with your actual detection rules.
   
   Author: Your Name
   Date: 2025-10-31
   Version: 1.0
*/

rule Multi_Custom_Example_Suspicious_Strings
{
    meta:
        description = "Example rule - detects suspicious string patterns"
        author = "Your Security Team"
        date = "2025-10-31"
        version = "1.0"
        severity = "medium"
        reference = "https://your-org.com/threat-intel"
        
    strings:
        // Example suspicious strings
        $cmd1 = "nc -e /bin/sh" ascii
        $cmd2 = "bash -i >& /dev/tcp/" ascii
        $cmd3 = "python -c 'import socket" ascii
        $cmd4 = "/bin/bash -c" ascii
        
        // Example hex patterns
        $hex1 = { 4D 5A 90 00 03 00 00 00 }  // PE header
        $hex2 = { 7F 45 4C 46 }              // ELF header
        
    condition:
        // Detect if any 2 suspicious commands are present
        2 of ($cmd*) or
        // Or if hex pattern is at file start with a command
        ($hex1 at 0 or $hex2 at 0) and 1 of ($cmd*)
}

rule Multi_Custom_Example_Network_Tools
{
    meta:
        description = "Example rule - detects common network tool usage"
        author = "Your Security Team"
        date = "2025-10-31"
        severity = "low"
        
    strings:
        $tool1 = "nmap" ascii wide
        $tool2 = "metasploit" ascii wide
        $tool3 = "msfvenom" ascii wide
        $tool4 = "netcat" ascii wide
        $tool5 = "socat" ascii wide
        
    condition:
        2 of them and filesize < 10MB
}

