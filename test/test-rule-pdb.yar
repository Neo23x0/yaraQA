import "pe"

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
      $s1 = "dummy,dummy,dummy" xor(0x01-0xff)
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
      $mz = { 4D 5A }
      $s1 = "dummy,dummy,dummy"
   condition:
      $mz at 0 and 1 of them
}

rule Demo_Rule_7_Path_Section_Fullword : APT {
   meta:
      description = "Rule that looks for a section of a path but uses fullword"
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\Section\\in\\Path\\" ascii fullword
   condition:
      1 of them
}

rule Demo_Rule_8_Noob_Rule : APT {
   meta:
      description = "Rule that has strings with a bunch of modifiers which indicate that the author had no idea what he was doing and just decided to use them all."
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "Usage: %s --killprocess" ascii wide nocase
   condition:
      1 of them
}

rule Demo_Rule_9_Uniform_String : APT {
   meta:
      description = "Rule that has strings which contents are very uniform / repetitive. This can cause problems with string matching resulting in 'too many string matches' errors."
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
   condition:
      1 of them
}

rule Demo_Rule_10_Fullword_Path : APT {
   meta:
      description = "Rule that has strings that seem to be a path segment and use fullword."
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\user.ini" fullword nocase
      $s2 = "\\\\SystemRoot\\test" fullword
   condition:
      uint16(0) == 0x5a4d and 1 of ($s*)
}

rule Demo_Rule_11_Fullword_Path_Duplicate : APT {
   meta:
      date = "2023-01-09"
      author = "Florian Roth (@cyb3rops)"
      score = 0
      description = "Rule that is logically equal to rule number 11 but has different meta data and string names"
      reference = "https://github.com/Neo23x0/yaraQA"
   strings:
      $s_dup1 = "\\USER.INI" fullword nocase
      $s_dup2 = "\\\\SystemRoot\\test" ascii fullword
   condition:
      1 of ($s_dup*) and uint16(0) == 0x5a4d
}

rule Demo_Rule_12_Only_PE : APT {
   meta:
      description = "Rule that is the only one in the set using the 'pe' module, which slows down the whole scan process"
      author = "Florian Roth (@cyb3rops)"
      date = "2023-01-09"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\USER.INI" fullword
   condition:
      pe.is_pe() and $s1
}
