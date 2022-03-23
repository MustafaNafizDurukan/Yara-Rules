rule Executing_Powershell_Command_Obfuscation_With_Backtick {
   meta:
      description = "Detects powershell files that is bigger than normal"
      author = "Mustafa Durukan"
      date = "23-03-2022"
   condition: 
      filesize > 5MB and
      file_extension == ".ps1"
}