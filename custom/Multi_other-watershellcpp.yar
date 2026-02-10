rule OTHER_WATERSHELLCPP
{
    meta:
        description = "Detect watershell firewall bypass (cpp variant)"
        author = "Jacob"
        confidence = "high"
        scope = "compiled ELF binary"

    strings:
        $flags = "phtl:" ascii
        $status = "status:" ascii

        $ioctl1 = "ioctl SIOCGIFFLAGS" ascii
        $ioctl2 = "ioctl SIOCGIFINDEX" ascii
        $ioctl3 = "ioctl SIOCSIFFLAGS" ascii

        $arp = "/proc/net/arp" ascii
        $route = "/proc/net/route" ascii
        $socketopt = "setsockopt" ascii

    condition:
        7 of them
}