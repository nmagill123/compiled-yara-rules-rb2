rule BACKDOOR_HEADSHOT
{
    meta:
        description = "Detect headshot module patched into nginx"
        author = "Tyler"
        confidence = "high"
        scope = "compiled ELF binary"

    strings:
        $module_name = "ngx_http_headshot_module" ascii
        $redir = {c7 00 20 32 3e 26 66 c7 40 04 31 00}
        $empty_res = "<-- no stderr/stdout from your command -->"
        
    condition:
        2 of them
}

