
rule Demo_Rule_1_Fullword_PDB : APT {
   meta:
      description = "Rule that has a problematic fullword modifier"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\i386\\mimidrv.pdb" ascii wide fullword
   condition:
      all of them
}

rule Demo_Rule_2_Short_Atom : APT {
   meta:
      description = "Rule that has a short atom"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = { 01 02 03 }
   condition:
      all of them
}

rule Demo_Rule_3_Fullword_FilePath_Section : APT {
   meta:
      description = "Rule that has a problematic fullword modifier"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\ZombieBoy\\" ascii fullword
   condition:
      all of them
}

rule Demo_Rule_4_Condition_Never_Matches : APT {
   meta:
      description = "Rule that looks for more strings than the rule actually has" 
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\ZombieBoy\\" ascii
   condition:
      2 of them
}

rule Demo_Rule_5_Condition_Short_String_At_Pos : APT {
   meta:
      description = "Rule that looks for a short string at a particular position"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $mz = "MZ" ascii
      $s1 = "dummy,dummy,dummy"
   condition:
      $mz at 0 and 1 of them
}

rule Demo_Rule_6_Condition_Short_Byte_At_Pos : APT {
   meta:
      description = "Rule that looks for a short byte string at a particular position"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $mz = { 4d 5a }
      $s1 = "dummy,dummy,dummy"
   condition:
      $mz at 0 and 1 of them
}

rule Demo_Rule_6_Condition_Short_Byte_At_Pos : APT {
   meta:
      description = "Rule that looks for a short byte string at a particular position"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\Section\\in\\Path\\" ascii fullword
   condition:
      1 of them
}

rule Demo_Rule_7_Noob_Rule : APT {
   meta:
      description = "Rule that has strings with a bunch of modifiers which indicate that the author had no idea what he was doing and just decided to use them all."
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "Usage: %s --killprocess" ascii wide nocase
   condition:
      1 of them
}
