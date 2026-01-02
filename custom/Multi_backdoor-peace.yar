rule BACKDOOR_PEACE_Ping
{
    meta:
        description = "Detect PEACE-patched ping with -E arbitrary command execution"
        author = "Tyler"
        confidence = "high"
        scope = "compiled ELF binary"

    strings:
        $help_flag =
            "-E <command>       leverage this utility's setuid bit to execute privileged arbitrary commands\n"
            ascii
        
        $env_path = "PATH=/bin:/usr/bin:/usr/local/bin" ascii
        $env_user = "USER=root" ascii

    condition:
        $help_flag
        and
        1 of ($env_path, $env_user)
}

