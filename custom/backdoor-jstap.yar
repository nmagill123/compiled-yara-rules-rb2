rule BACKDOOR_JSTAP
{
    meta:
        description = "Detect JSTAP web backdoor"
        author = "Tyler"
        confidence = "high"
        scope = "javascript file"

    strings:
        $server_var = "window.taperexfilServer" ascii
        $sess_key = "taperSessionUUID" ascii

        // endpoints
        $p1 = "/loot/html/" ascii
        $p2 = "/loot/location/" ascii
        $p3 = "/client/metrics/" ascii
        $p4 = "/client/fingerprint/" ascii
    condition:
        ($server_var or $sess_key)
        and
        1 of ($p1,$p2,$p3,$p4)
        or
        all of ($p*)
}

