rule OTHER_RUSYKEYS
{
    meta:
        description = "Detect rustykeys keylogger"
        author = "Tyler"
        confidence = "medium"
        scope = "compiled ELF binary"

    strings:
        $km = { 31 21 32 40 33 23 34 24 35 25 36 5e 37 26 38 2a 39 28 30 29 5b 7b 5d 7d 2f 3f 3d 2b 5c 7c 27 22 2c 3c 2e 3e 60 7e 2d 5f }
        $panic = "SystemTime before UNIX EPOCH!" ascii

        $winlog = "C:\\Windows\\Logs\\SIH\\SIH.20240307.162282.822.1" ascii
        $linlog = "/var/lib/.Xsock" ascii

        $fn = "start_keylogger" ascii
        $rust = "Result::unwrap()" ascii

    condition:
        3 of them
}
