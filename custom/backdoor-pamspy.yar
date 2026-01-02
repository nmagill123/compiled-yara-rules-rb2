rule EBPF_PAM_get_authtok
{
    meta:
        description = "High-confidence detection of eBPF probes targeting pam_get_authtok"
        author = "Tyler"
        confidence = "high"

    strings:
        $uprobe    = "uprobe/pam_get_authtok" ascii
        $uretprobe = "uretprobe/pam_get_authtok" ascii

        $btf   = ".BTF" ascii
        $btfext = ".BTF.ext" ascii

    condition:
        ( any of ($uprobe, $uretprobe) )
        and 1 of ($btf, $btfext)
}
