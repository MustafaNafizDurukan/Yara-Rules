rule Executing_Powershell_Command_Obfuscation_With_Backtick : T1027 {
   meta:
      description = "Detects powershell code that use backtick for obduscation"
      author = "Mustafa Durukan"
      date = "23-03-2022"
      example = "${j`ustAV`a`r} = \"some value\""
   strings:
      $x1 = "${"
      $x2 = "`"
      $x3 = "="
   condition: 
      filesize < 5MB and 
      file_extension == ".ps1" and
      all of ( $x* ) and 
      ( @x1 < @x2 and @x2 < @x3 ) and
      #x2 > 1
}