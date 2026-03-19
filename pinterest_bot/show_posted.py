import json
from pathlib import Path

posted = json.loads(Path('posted_pins.json').read_text())
print(f'{len(posted)} pins posted:\n')
for p in posted:
    print(f"  [{p['posted_at'][:10]}] {p['title']}")
    print(f"           Pin ID: {p['pin_id']}")
    print()
