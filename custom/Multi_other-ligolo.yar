rule LIGOLO_NG
{
    meta:
        description = "Ligolo network pivoting tool"
        author = "Tyler"
        confidence = "high"

    strings:
        $ligolo = "ligolo" ascii
        $git = "github.com/nicocha30" ascii
        $golang = "golang" ascii

        $warn = "Connection lost. Attempting to reconnect..." ascii
        $error = "could not get network interfaces" ascii
    condition:
        3 of them
}
