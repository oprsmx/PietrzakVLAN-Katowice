# drop-host-v2.rsc
# MikroTik RouterOS Script - Permanent block z 5 fazami czyszczenia
# Użycie: :global HOSTID "MAC lub IP"; /system script run drop-host-v2
# Dokumentacja: drop_host_v2_documentation.html

/system script add name=drop-host-v2 policy=\
ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="\
:global HOSTID;\r\
:if ([:len \$HOSTID] = 0) do={ :log error \"drop-host-v2: ustaw najpierw :global HOSTID \\\"MAC lub IP\\\"\"; :put \"Użycie: :global HOSTID \\\"34:29:8F:74:EC:46\\\"; /system script run drop-host-v2\"; :return }\r\
\r\
:local target \$HOSTID;\r\
:local isMac false;\r\
:if ([:find \$target \":\"] != -1) do={ :set isMac true; :set target [:toupper \$target] }\r\
\r\
:local foundIP \"\";\r\
:local foundMAC \"\";\r\
\r\
# Rozpoznaj po MAC albo IP\r\
:if (\$isMac = true) do={\r\
  :set foundMAC \$target;\r\
  :local lId [/ip dhcp-server lease find mac-address=\$foundMAC];\r\
  :if ([:len \$lId] > 0) do={ :set foundIP [/ip dhcp-server lease get \$lId address] }\r\
} else={\r\
  :set foundIP \$target;\r\
  :local lId2 [/ip dhcp-server lease find address=\$foundIP];\r\
  :if ([:len \$lId2] > 0) do={ :set foundMAC [/ip dhcp-server lease get \$lId2 mac-address] } else={\r\
    :local bh [/interface bridge host find where address=\$foundIP];\r\
    :if ([:len \$bh] > 0) do={ :set foundMAC [/interface bridge host get \$bh mac-address] }\r\
  }\r\
}\r\
\r\
:log info (\"drop-host-v2: cel=\" . \$HOSTID . \" -> IP=\" . \$foundIP . \", MAC=\" . \$foundMAC);\r\
\r\
# A) ARP\r\
:if ([:len \$foundIP] > 0) do={ :local a1 [/ip arp find where address=\$foundIP]; :if ([:len \$a1] > 0) do={ /ip arp remove \$a1; :log info (\"drop-host-v2: ARP usunięty dla IP \" . \$foundIP) } }\r\
:if ([:len \$foundMAC] > 0) do={ :local a2 [/ip arp find where mac-address=\$foundMAC]; :if ([:len \$a2] > 0) do={ /ip arp remove \$a2; :log info (\"drop-host-v2: ARP usunięty dla MAC \" . \$foundMAC) } }\r\
\r\
# B) DHCP lease\r\
:if ([:len \$foundMAC] > 0) do={ :local d1 [/ip dhcp-server lease find where mac-address=\$foundMAC]; :if ([:len \$d1] > 0) do={ /ip dhcp-server lease remove \$d1; :log info (\"drop-host-v2: lease DHCP usunięty (MAC) \" . \$foundMAC) } }\r\
:if ([:len \$foundIP] > 0) do={ :local d2 [/ip dhcp-server lease find where address=\$foundIP]; :if ([:len \$d2] > 0) do={ /ip dhcp-server lease remove \$d2; :log info (\"drop-host-v2: lease DHCP usunięty (IP) \" . \$foundIP) } }\r\
\r\
# C) Bridge host (L2)\r\
:if ([:len \$foundMAC] > 0) do={ :local bh1 [/interface bridge host find where mac-address=\$foundMAC]; :if ([:len \$bh1] > 0) do={ /interface bridge host remove \$bh1; :log info (\"drop-host-v2: bridge-host usunięty dla MAC \" . \$foundMAC) } }\r\
:if ([:len \$foundIP] > 0) do={ :local bh2 [/interface bridge host find where address=\$foundIP]; :if ([:len \$bh2] > 0) do={ /interface bridge host remove \$bh2; :log info (\"drop-host-v2: bridge-host usunięty dla IP \" . \$foundIP) } }\r\
\r\
# D) Conntrack (NAT/sesje)\r\
:if ([:len \$foundIP] > 0) do={\r\
  :local c1 [/ip firewall connection find where src-address~(\\\"^\" . \$foundIP . \\\"(:|$)\\\")];\r\
  :if ([:len \$c1] > 0) do={ /ip firewall connection remove \$c1; :log info (\"drop-host-v2: conntrack rm src=\" . \$foundIP) }\r\
  :local c2 [/ip firewall connection find where dst-address~(\\\"^\" . \$foundIP . \\\"(:|$)\\\")];\r\
  :if ([:len \$c2] > 0) do={ /ip firewall connection remove \$c2; :log info (\"drop-host-v2: conntrack rm dst=\" . \$foundIP) }\r\
}\r\
\r\
# E) Twarda blokada L2 po MAC (PERMANENT BLOCK)\r\
:if ([:len \$foundMAC] > 0) do={\r\
  :local tag (\"drop-host-v2 block \" . \$foundMAC);\r\
  :local old [/interface bridge filter find where comment=\$tag];\r\
  :if ([:len \$old] = 0) do={ /interface bridge filter add chain=forward mac-src=\$foundMAC action=drop comment=\$tag; :log info (\"drop-host-v2: dodano blokadę L2 dla MAC \" . \$foundMAC) } else={ :log info (\"drop-host-v2: blokada L2 już istnieje dla MAC \" . \$foundMAC) }\r\
}\r\
\r\
:put (\"drop-host-v2: OK -> IP=\" . \$foundIP . \", MAC=\" . \$foundMAC)"
