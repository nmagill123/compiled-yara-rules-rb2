rule OTHER_SSHSNAKE 
{
    meta:
        description = "Detect ssh snake worm"
        author = "Tyler"
        confidence = "high"
        scope = "bash script"

    strings:
        $f1 = "use_combinate_interesting_users_hosts" ascii
        $f2 = "use_combinate_users_hosts_aggressive" ascii
        $url = "https://github.com/MegaManSec/SSH-Snake" ascii
    
    condition:
        2 of them
}
