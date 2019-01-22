## Snort detection rules for APT related user agents

#### Original idea taken from sigma(SIEM) rule written by Florian Roth.

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20SJZJ\x20\x28compatible\x3b\x20MSIE\x206\x2e0\x3b\x20Win32\x29"; 
	content:"User-Agent: SJZJ (compatible; MSIE 6.0; Win32)";
)

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20Mozilla\/5\x2e0\x20\x28(Windows|Windows\x20NT\x20(6|6\x2e2|3)|compatible)\x3b\x20WOW64\x3b\x20rv\x3a(20|28)\x2e0\x29\x20Gecko\/20100101\x20(Firefox\/|Firefox\/2|20\x2e0|28\x2e0))"; 
	content:"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/)";
) 

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20Mozilla\/5\x2e0\x20\x28Windows\x3b\x20U\x3b\x20Windows\x20NT\x205\x2e1\x3b\x20zh\x2dEN\x3b\x20rv\x3a1\x2e7\x2e12\x29\x20(Gecko\/200|Gecko\/20100719\x20Firefox\/1\x2e0\x2e7)"; 
	content:"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200";
) #funciona

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20(Netscape\x29|Mozilla\/5\x2e0\x28Windows\x3b\x20U\x3b\x20Windows\x20NT\x205\x2e1\x3b\x20en\x2dUS\x3b\x20rv\x3a1\x2e9\x2e2\x2e13\x29\x20Firefox\/3\x2e6\x2e13\x20GTB7\x2e1)"; 
	content:"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Firefox/3.6.13 GTB7.1";
) 

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20Mozilla\/(4|5)\x2e0\x20\x28compatible\x3b\x20MSIE\x20(7\x2e4\x3b\x20Win32\x3b32\x2dbit|9\x2e0\x3b\x20Windows\x20NT\x206\x2e1\x3b\x20WOW64\x3b\x20Trident\/5\x2e0|8\x2e0\x3b\x20Windows\x20NT\x206\x2e1\x3b\x20(Trident\/4\x2e0\x3b\x20SLCC|WOW64\x3b\x20Trident\/4\x2e0\x3b\x20SLCC2\x3b\x20\x2eNETCLR\x202\x2e0\x2e50727))\x29"; 
	content:"Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)";
) 

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20Mozilla\/4\x2e0\x20\x28compatible\x3b\x20MSIE\20(8\x2e0\x3b\x20Windows\x20NT\x206\x2e0\x3b\x20SV1|11\x2e0\x3b\x20Windows\x20NT\x206\2e1\x3b\x20SV1)\x29"; 
	content:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)";
) 

alert tcp $EXT_NET any -> $INTRANET $HTTP_PORTS (
	msg:"APT User-Agent Detected"; 
	http_header; 
	fast_pattern:only; 
	pcre:"/^User\x20Agent\x3a\x20Mozilla\/4\x2e0\x20\x28compatible\x3b\x20(MSIE\x208\x2e0\x3b\x20Win32|MSI\x206\x2e0\x3b|MSIE\x207\x2e4\x3b\x20Win32\x3b32\x2dbit)\x29"; 
	content:"Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)";
) 
