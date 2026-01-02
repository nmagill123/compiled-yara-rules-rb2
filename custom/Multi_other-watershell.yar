rule OTHER_WATERSHELL
{
    meta:
        description = "Detect watershell firewall bypass"
        author = "Jacob"
        confidence = "medium"
        scope = "compiled ELF binary"

    strings:

        $running = "Doing the thing: %s" ascii
        $listening = "Listening on %s" ascii
        $args = "phi:l:" ascii

    condition:
        all of them
}
