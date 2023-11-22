
rule CISA_10478915_01 : trojan installs_other_components {
   meta:
      author = "CISA Code & Media Analysis"
      incident = "10478915"
      date = "2023-11-06"
      last_modified = "20231108_1500"
      actor = "n/a"
      family = "n/a"
      capabilities = "installs-other-components"
      malware_Type = "trojan"
      tool_type = "information-gathering"
      description = "Detects trojan .bat samples"
      sha256 = "98e79f95cf8de8ace88bf223421db5dce303b112152d66ffdf27ebdfcdf967e9"
   strings:
      $s1 = { 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 7a 2e 74 78 74 }
      $s2 = { 72 65 67 20 73 61 76 65 20 68 6b 6c 6d 5c 73 79 73 74 65 6d 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 65 6d }
      $s3 = { 6d 61 6b 65 63 61 62 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 61 2e 70 6e 67 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 61 2e 63 61 62 }
   condition:
      all of them
}
