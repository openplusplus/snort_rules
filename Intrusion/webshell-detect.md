# Snort rule for webshell execution via GET parameters

alert tcp $EXTERNAL_NET any -> $INTRANET $HTTP_PORTS (
	msg:"Possible Webshell detected";
	sid:xxxx;
	rev:xxx;
	http-req-uri;
	prce:"(\x3dcmd\x2520\x2fc\x2520|\x3dnet\x2520user|\x3dwhoami|\x3dcat\x2520\/etc\/passwd|\x3dwget)";
)
