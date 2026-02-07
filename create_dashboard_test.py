import json
import datetime

# Create a history file for "yesterday"
# We'll make sure "New" threats appear today by omitting them from yesterday
data = []

# "Old" threats (present yesterday)
data.extend([{"date": "2026-02-06", "threat_tag": "OldThreat1"}] * 100)
data.extend([{"date": "2026-02-06", "threat_tag": "OldThreat2"}] * 50)

with open("threat_feed_2026-02-06.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4)

print("Created threat_feed_2026-02-06.json")
