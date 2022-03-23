rule Downloading_File_by_MSHTA : T1218 {
   meta:
      description = "Detects downloader script by using mshta.exe"
      author = "Mustafa Durukan"
      date = "23-03-2022"
   strings:
      $x1 = "mshta" nocase ascii wide
      $x2 = "script:" nocase ascii wide
      
      $s2 = "http" nocase ascii wide
      $s2 = "ftp" nocase ascii wide
      $s3 = "github" nocase ascii wide
      $s4 = "gitlab" nocase ascii wide
      $s4 = "bitbucket" nocase ascii wide
      $s4 = "sourceforge" nocase ascii wide
      $s4 = "launchpad" nocase ascii wide
      $s4 = "cloud.google" nocase ascii wide
      $s4 = "aws.amazon" nocase ascii wide
   condition: 
      filesize < 5MB and 
      all of ( $x* ) and 
      1 of ( $s* ) and
      ( @x1 < @x2 ) and
}