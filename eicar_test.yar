rule Eicar_Test {
   meta:
      description = "EICAR"
      author = "RR"
 
   strings:
      $s1 = "^X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
   condition:
      uint16(0) == 0x3558 and filesize < 70 and $s1 at 0
}
