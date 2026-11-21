// SHA-256 values identify the reference samples. The rules match file content.

rule IR_ELF_Devnode_Syncd
{
    meta:
        description = "Detects the devnode-syncd sample using flow collector strings"
        sample = "devnode-syncd"

    strings:
        $config = "/etc/flow/config.yaml"
        $flow_hook = "[flow] attached tc hook on %s (ifindex %d), sampling 1:%d"
        $flow_ring = "[flow] ring buffer: %d events processed, %d dropped"
        $flow_fallback = "[flow] warning: raw socket fallback for export (udp send failed)"

    condition:
        2 of them
}

rule IR_ELF_Neigh_Gcd
{
    meta:
        description = "Detects the packed neigh-gcd sample using its body and trailer"
        sample = "neigh-gcd"

    strings:
        // The packed body is shared with net-pathd. The trailer differs.
        $packed_body = { 0C 8B F6 64 F3 1C C3 67 F8 61 FA 1F 46 FC 05 B5 C2 86 5A B6 CC 27 7D 8E }
        $trailer_1 = { 4D 95 F3 66 70 BA 2D 47 B7 7C 6B A8 AE C1 AA 6E E5 72 44 95 7F 5C 72 FE }
        $trailer_2 = { D5 0A EE F3 D5 09 C5 0F 9B 8B DC 8F 3D 39 5E FF 2E 88 57 46 E9 9D 1F DA }

    condition:
        2 of them
}

rule IR_ELF_Net_Pathd
{
    meta:
        description = "Detects the packed net-pathd sample using its body and trailer"
        sample = "net-pathd"

    strings:
        // The packed body is shared with neigh-gcd. The trailer differs.
        $packed_body = { 0C 8B F6 64 F3 1C C3 67 F8 61 FA 1F 46 FC 05 B5 C2 86 5A B6 CC 27 7D 8E }
        $trailer_1 = { 9A 5D A0 97 F2 8B 14 82 03 C5 50 43 6B 3B 20 BB 0B E0 95 D7 74 2C CA 72 }
        $trailer_2 = { 3C 10 9C FB 4B 7A DF 1A 6F 25 A9 0A F7 3E CF 4C 7A C0 82 1C 70 6E 0C 81 }

    condition:
        2 of them
}

rule IR_ELF_Net_Uevtd
{
    meta:
        description = "Detects the packed net-uevtd sample using bytes from its compressed body"
        sample = "net-uevtd"

    strings:
        $packed_1 = { E3 14 9A E7 25 75 9A F3 E0 CD 97 1A 9A 52 3E 09 CC 7D 56 F3 6E B8 01 7D }
        $packed_2 = { 7B 33 81 44 2A 07 87 61 BB 17 8F DD A1 01 92 FE 0E 56 6C FE 9F 53 95 56 }
        $packed_3 = { 70 3A F8 AB 18 0B AC 35 3C DD 01 84 7F 29 C4 B9 A8 52 0A 72 92 F6 A1 3F }

    condition:
        2 of them
}
