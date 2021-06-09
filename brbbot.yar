
rule brbbotMalware
{
    strings:
        $a1 = "brbconfig.tmp"
        $a2 = "exec"
        $a3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
		$a4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
		$a5 = "sleep"
		$a6 = "brbbot"
		
		$b1 = "IsDebuggerPresent"
		$b2 = "GetComputerName"
		$b3 = "GetSystemDirectory"
		$b4 = "RegOpenKeyEx"
		$b5 = "RegSetValueEx"
		$b6 = "GetCurrentThreadId"
    condition:
        all of ($a*) and
		4 of ($b*) and
		uint16(0) == 0x5A4D and
		uint32(uint32(0x3C)) == 0x00004550 and
		filesize < 20MB
		filesize < 20MB
}