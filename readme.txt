 How to Enable Strict Mode

Standard (strict, no shuffling)

python cisco_sanitizer.py running-config.txt safe-config.txt
or
python cisco_sanitizer.py running-config.txt safe-config.txt --mode=standard


MAX (maximum paranoia)

Shuffles interfaces/ACLs/routes, adds fake entries, removes comments, fully anonymizes names.


python cisco_sanitizer.py running-config.txt safe-config.txt --max
 or
python cisco_sanitizer.py running-config.txt safe-config.txt --mode=max

Different salts per project

Maps the same real IP to different fake IPs:

python cisco_sanitizer.py run1.txt safe1.txt --max --salt=proj1_secret
python cisco_sanitizer.py run2.txt safe2.txt --max --salt=proj2_secret
