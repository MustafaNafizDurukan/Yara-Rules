rule Executing_VBScript_by_MSHTA : T1218 {
   meta:
      description = "Detects script that runs vbscript by using mshta.exe"
      author = "Mustafa Durukan"
      date = "23-03-2022"
   strings:
      $x1 = "mshta" nocase ascii wide
      $x2 = "vbscript:" nocase ascii wide
   condition: 
      filesize < 5MB and 
      all of ( $x* ) and 
      ( @x1 < @x2 )
}