# Snort rule for fallchill and vollgmer. 

## APT Hiddencobra implants

alert tcp $EXTERNAL_NET any <> $HOME_NET $HTTP_PORTS (
    msg:"Possible fallchill-vollgmer traffic detected ";
    sid:xxx;
    gid:xx;
    prce:"\x17\x03\x01\x00\x08.{4}(\x04\x88\x4d\x76|\x06\x88\x4d\x76|\xb2\x63\x70\x7b|\xb0\x63\x70\x7b)";
    reference:"https://www.us-cert.gov/ncas/alerts/TA17-318B";
)


alert tcp $EXTERNAL_NET any <> $HOME_NET $HTTP_PORTS (
    msg:"Possible fallchill-vollgmer traffic detected ";
    sid:xxx;
    gid:xx;
    prce:"\x17\x03\x01\x00\x08.{4}(\x04\x88\x4d\x76|\x06\x88\x4d\x76|\xb2\x63\x70\x7b|\xb0\x63\x70\x7b)";
    reference:"https://www.us-cert.gov/ncas/alerts/TA17-318B";
)

alert tcp $EXTERNAL_NET any <> $HOME_NET $HTTP_PORTS (
    msg:"Possible fallchill-vollgmer traffic detected ";
    sid:xxx;
    gid:xx;
    content:"Mozillar/";
    reference:"https://www.us-cert.gov/ncas/alerts/TA17-318B";
)

alert tcp any any -> any any (
    msg:"Malformed_UA"; 
    content:"User-Agent: Mozillar/"; 
    depth:500; 
    sid:xxx;
    reference:"https://www.us-cert.gov/ncas/alerts/TA17-318B";
)

alert tcp $EXTERNAL_NET any <> $HOME_NET $HTTP_PORTS (
    msg:"Possible fallchill-vollgmer traffic detected ";
    sid:xxx;
    gid:xx;
    prce:"\x18\x17\xe9\xe9\xe9\xe9";
    reference:"https://www.us-cert.gov/ncas/alerts/TA17-318B";
)

alert tcp $EXTERNAL_NET any <> $HOME_NET $HTTP_PORTS (
    msg:"Possible fallchill-vollgmer traffic detected ";
    sid:xxx;
    gid:xx;
    prce:"(\x18|\x1b)\x17\xe9\xe9\xe9\xe9";
    reference:"https://www.us-cert.gov/ncas/alerts/TA17-318B";
)
