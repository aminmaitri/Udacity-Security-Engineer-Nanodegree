rule unknown_threat
{
meta:
	author = "@mk"
strings:
     $url = "darkl0rd.com:7758"
condition:
     all of them
}
