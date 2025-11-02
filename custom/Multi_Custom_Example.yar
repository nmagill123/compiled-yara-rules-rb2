rule imix {
    meta:
        author = "Tyler"
        description = "checks whether or not the imix implant from the realm c2 is present through checking dependencies"
    
    strings:
        // strings from dependencies
        $b = "Press [ENTER] / [RETURN] to continue..." // clap
        $d = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" // ring
        $e = "https://github.com/bazelbuild/starlark/blob/master/spec.md#dict" // starlark
        $f = "Hellenic Academic and Research Institutions Cert. Authority" // webpki
    condition:
        3 of them
}