
/* DS1 - duplicate strings */

rule DS1_Duplicate_Strings {
   meta:
      description = "Contains duplicate strings (DS1): $s2 = $s1, $s4 = $s3, $x2 = $x1"
   strings:
      $s1 = "evil.example.org" ascii
      $s2 = "evil.example.org"           // same as $s1 ('ascii' is the default)
      $s3 = "EVIL.example.ORG" nocase
      $s4 = "evil.example.org" nocase    // same as $s3
      $s5 = "evil.example.org" wide      // no duplicate (different modifier)
      $x1 = { 4D 5A 90 00 03 00 }
      $x2 = { 4d 5a 90 00 03 00 }        // same as $x1
   condition:
      uint16(0) == 0x5a4d and 2 of them
}

rule DS1_Duplicate_Anonymous_Strings {
   meta:
      description = "Contains a duplicate anonymous string (DS1)"
   strings:
      $ = "cmd.exe /c whoami"
      $ = "cmd.exe /c whoami"
   condition:
      all of them
}

/* DU1 - logical duplicates (different names, string order and modifier order) */

rule DU1_Duplicate_Rule_A {
   meta:
      description = "Logical duplicate of DU1_Duplicate_Rule_B (DU1)"
   strings:
      $a = "Invoke-Mimikatz" ascii wide
      $b = "sekurlsa::logonpasswords" ascii
   condition:
      filesize < 2MB and 1 of them
}

rule DU1_Duplicate_Rule_B {
   meta:
      description = "Logical duplicate of DU1_Duplicate_Rule_A (DU1)"
   strings:
      $x1 = "sekurlsa::logonpasswords"
      $x2 = "Invoke-Mimikatz" wide ascii
   condition:
      1 of them and filesize < 2MB
}

/* HS3 / HS4 - many regular expressions */

rule HS3_Three_Regex_Strings {
   meta:
      description = "Uses 3 regular expressions (HS3)"
   strings:
      $r1 = /gate\.php\?id=[0-9]{4,8}/
      $r2 = /User-Agent: Mozilla\/[0-9]\.[0-9]/
      $r3 = /POST \/upload\.php\?name=[a-z]{4,8}/
   condition:
      all of them
}

rule HS4_Five_Regex_Strings {
   meta:
      description = "Uses 5 regular expressions (HS4)"
   strings:
      $r1 = /gate\.php\?id=[0-9]{4,8}/
      $r2 = /User-Agent: Mozilla\/[0-9]\.[0-9]/
      $r3 = /POST \/upload\.php\?name=[a-z]{4,8}/
      $r4 = /Cookie: session=[a-f0-9]{16}/
      $r5 = /\/panel\/login\.php\?user=[a-z]{3,10}/
   condition:
      all of them
}
