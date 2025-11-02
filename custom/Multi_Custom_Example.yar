rule imix {
    meta:
        author = "Tyler"
        description = "checks whether or not the imix implant from the realm c2 is present through checking dependencies"
    
    strings:
        // strings from dependencies
        $a = "invalid rule day julian day" // chrono
        $b = "Press [ENTER] / [RETURN] to continue..." // clap
        $c = "IPSec/IKE/Oakley curve #3 over a 155 bit binary field." // openssl
        $d = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" // ring
        $e = "https://github.com/bazelbuild/starlark/blob/master/spec.md#dict" // starlark
        $f = "Hellenic Academic and Research Institutions Cert. Authority" // webpki
    condition:
        all of them
}