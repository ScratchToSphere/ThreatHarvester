import json
import datetime

data = []
# 6000 Mozi
data.extend([
    {
        "date": "2026-02-06 10:00:00",
        "ioc_value": "1.2.3.4",
        "ioc_type": "ip:port",
        "threat_tag": "32-bit,elf,mips,Mozi",
        "source": "FeodoTracker",
        "country": "Unknown"
    }
] * 6000)

# 1600 Mirai
data.extend([
    {
        "date": "2026-02-06 10:00:00",
        "ioc_value": "1.2.3.5",
        "ioc_type": "ip:port",
        "threat_tag": "elf,mirai,ua-wget",
        "source": "FeodoTracker",
        "country": "Unknown"
    }
] * 1600)

with open("threat_feed_2026-02-06.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4)

print("Created threat_feed_2026-02-06.json with 7600 entries.")
