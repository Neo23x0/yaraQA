/*
 This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
rule Jupyter_Infostealer_PowerShell
{
   meta:
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "observed powershell command strings"
        reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html" 
  strings:
      $a = /\[.\..\]::run\(\)/ nocase
      $b = /\[.\..\]::run\(\)/ nocase wide
      $c = "[Reflection.Assembly]::Load("
      $d = /\[[a-zA-Z0-9\._]{25,45}\]::[a-zA-Z0-9\._]{10,25}\(\)/
  condition:
      ($a or $b) or ($c and $d)
}

rule SUSP_Bad_Regex_Sep23 {
    meta:
        description = "Detects a bad regex"
        author = "Noob"
        reference = "https://github.com/gabe-k/themebleed"
        score = 75
    strings:
        $sr1 = /[\w\-.]{1,3}@[\w\-.]{1,3}/
    condition:
        $sr1
}

