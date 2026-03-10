rule C2_SENTINEL
{
    meta:
        description = "Detect raw socket sentinel c2"
        author = "Tyler"
        confidence = "high"
        scope = "compiled ELF binary"

    strings:
        $projectName = "saprus" ascii
        $implantName = "sentinel" ascii

        $info1 = "Starting Sentinel" ascii
        $info2 = "Using randomly generated name:" ascii
        $panic = "Error finding the interface by name:" ascii

        $creature = "MindFlayer" ascii

        $golang = "Go build" ascii
        $bpfDep = "golang.org/x/net/bpf" ascii
        $packetDep = "github.com/mdlayher/packet" ascii
    condition:
        4 of them
}
