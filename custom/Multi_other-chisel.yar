rule CHISEL
{
    meta:
        description = "Chisel network pivoting tool"
        author = "Tyler"
        confidence = "high"

    strings:
        $chisel = "chisel" ascii
        $git = "github.com/jpillora" ascii
        $golang = "golang" ascii

        $error2 = "Failed to decode remote '%s': %s" ascii
        $error1 = "Error loading client cert and key pair: %v" ascii
    condition:
        3 of them
}
