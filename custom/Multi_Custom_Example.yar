rule imix {
    meta:
        author = "Tyler"
        description = "checks whether or not the imix implant from the realm c2 is present through checking dependencies"
    strings:
        $a = "invalid rule day julian day" 
        $b = "Press [ENTER] / [RETURN] to continue..." 
        $c = "IPSec/IKE/Oakley curve #3 over a 155 bit binary field."
        $d = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" 
        $e = "https://github.com/bazelbuild/starlark/blob/master/spec.md#dict" 
        $f = "Hellenic Academic and Research Institutions Cert. Authority" 
    condition:
        all of them
}