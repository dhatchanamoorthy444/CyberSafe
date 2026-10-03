# Security Vendors adapter base — genuine integration layer
# Provider-specific modules import this; only configured providers run.

VENDOR_LIST = [
    "Abusix","Acronis","ADMINUSLabs","AILabs (MONITORAPP)","AlienVault",
    "Antiy-AVL","BitDefender","BlockList","Blueliv","Certego",
    "Chong Lua Dao","CINS Army","CRDF","Criminal IP","CTX AI",
    "Cyble","CyRadar","desenmascara.me","Dr.Web","EmergingThreats",
    "Emsisoft","ESET","ESTsecurity","Forcepoint ThreatSeeker","Fortinet",
    "G-Data","Google Safe Browsing","GreenSnow","Heimdal Security",
    "IPsum","Juniper Networks","Kaspersky","LevelBlue","Lionic",
    "Malwared","MalwarePatrol","OpenPhish","PhishTank","PREBYTES",
    "Quick Heal","Quttera","Rising","Sangfor","Scantitan",
    "SCUMWARE.org","Seclookup","Sophos","StopForumSpam",
    "Sucuri SiteCheck","ThreatHive","URLhaus","Viettel Threat Intelligence",
    "ViriBack","VX Vault","Webroot","Xcitium Verdict Cloud","Yandex Safebrowsing",
    "ZeroCERT","0xSI_f33d","alphaMountain.ai","AlphaSOC",
    "ArcSight Threat Intelligence","AutoShun","Bfore.Ai PreCrime",
    "Bkav","ChainPatrol","CSIS Security Group","Cyan","DNS8",
    "Ermes","Fortra","GCP Abuse Intelligence","GreyNoise","Gridinsoft",
    "Guardpot","Hunt.io Intelligence","K7AntiVirus","Lumu","MalwareURL",
    "Mimecast","Netcraft","PhishFort","PrecisionSec","SafeToOpen",
    "Sansec eComscan","Snort IP sample list","SOCRadar","URLQuery",
    "VIPRE","ZeroFox",
]

# Normalized schema: vendor(str), status(str), checked(bool), indicator_type(str),
# details(str), error(str|None), source_timestamp(str|None)

STATUSES = ["clean","malicious","suspicious","unrated","not_checked","error"]
