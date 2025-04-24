# @@query@@ : http://testphp.vulnweb.com/artists.php?artist=1
# @@type@@ : WEAK / VULN
#"><script~~blahblah
# @@target@@ : http://testphp.vulnweb.com/artists.php?artist=1
# @@query@@ : artist
# @@type@@ : WEAK / VULN
# slack.sh @@query@@ @@type@@

query=$1
type=$2
if [ $type = "VULN" ]
then
  curl -X POST --data-urlencode "payload={\"channel\": \"#yourchannel\", \"username\": \"Dalfox\", \"text\": \"[Verify]\n$query\", \"icon_emoji\": \"fox\"}" https://hooks.slack.com/services/your/secret_url
else
  curl -X POST --data-urlencode "payload={\"channel\": \"#yourchannel\", \"username\": \"Dalfox\", \"text\": \"[Reflected]\n$query\", \"icon_emoji\": \":fox:\"}" https://hooks.slack.com/services/your/secret_url
fi
