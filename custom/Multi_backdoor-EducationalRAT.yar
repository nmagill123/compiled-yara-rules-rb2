rule BACKDOOR_EDUCATIONALRATPY
{
    meta:
        description = "EducationalRAT c2 client"
        author = "Adam"
        date = "3/8/2026"
        confidence = ""
        scope = "python file"

    strings:
        $cmd1 = "ShellExecute" ascii
        $cmd2 = "GetCommand" ascii
        $cmd3 = "def Download" ascii
        $cmd4 = "def Upload" ascii

        $py1 = "requests.post(url, files=files)" ascii
        $py2 = "open(fileName,'wb').write(requests.get(url).content)" ascii
        $py3 = "requests.get(c2)" ascii
    
    condition:
        5 of them
}

rule BACKDOOR_EDUCATIONALRATPS1
{
    meta:
        description = "EducationalRAT c2 client .ps1 variant"
        author = "Adam"
        date = "3/8/2026"
        confidence = ""
        scope = ".ps1 file"

    strings:
        $cmd1 = "Shell-Execute" ascii
        $cmd2 = "Get-Command" ascii
        $cmd3 = "function Download" ascii
        $cmd4 = "function Upload" ascii

        $ps1 = "IEX "$cmd"" ascii
        $ps2 = "$cmdString = Get-Command c2" ascii
        $ps3 = "(New-Object System.Net.WebClient).DownloadString($c2)" ascii
    
    condition:
        5 of them
}

rule BACKDOOR_EDUCATIONALRATEXE
{
    meta:
        description = "EducationalRAT c2 client" .exe variant
        author = "Adam"
        date = "3/8/2026"
        confidence = "low"
        scope = "compiled binary"

    strings:
        $cmd1 = "Command was recieved but there is either no RAT command" ascii
        $cmd2 = "Args Recieved::" ascii
        $cmd3 = "UploadOutput" ascii
        $cmd4 = "RattyMcRatFace.Properties.Resources.resources" ascii

        $rat = "RattyMcRatFace" ascii
    
    condition:
        3 of them
        or $rat
}
