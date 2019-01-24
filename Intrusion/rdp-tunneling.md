# Snort rules for RDP Tunneling detection

alert tcp any [21,22,23,25,53,80,443,8080] -> any !3389 (
msg:"RDP - HANDSHAKE [Tunneled msts]"; dsize:<65; content:"|03 00 00|"; depth:3; 
content:"|e0|"; distance:2; within:1; content:"Cookie: mstshash="; distance:5; within:17; sid:1; rev:1;
)

alert tcp any [21,22,23,25,53,80,443,8080] -> any !3389 (
msg:"RDP - HANDSHAKE [Tunneled]"; flow:established; content:"|c0 00|Duca"; depth:250; 
content:"rdpdr"; content:"cliprdr"; sid:2; rev:1;
)

[Source](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)
