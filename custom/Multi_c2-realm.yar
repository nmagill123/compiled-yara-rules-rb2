rule C2_REALM_IMIX
{
    meta:
        description = "Detect imix realm c2 implant"
        author = "Tyler"
        confidence = "high"
        scope = "compiled ELF binary"

    strings:
        $old_dsl = "github.com/bazelbuild/starlark" ascii
        $build_str = "imix-git-vendor" ascii
        $build_strv2 = "imixv2-git-vendor" ascii
        
        $tokio = "tokio" ascii
        $imix = "imix" ascii
        $dsl = "eldritch" ascii
        
        // only one transport by default based on feature flags
        $transport_grpc = "implants/lib/transport/src/grpc.rs" ascii
        $transport_http = "implants/lib/transport/src/http.rs" ascii
    
    condition:
        3 of them
}
