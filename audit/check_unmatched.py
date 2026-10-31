import json
rows = [json.loads(l) for l in open('work/data/ghsa-eval/labels.jsonl', encoding='utf-8')]
for idx in [23, 25, 30, 85, 121]:
    r = rows[idx]
    print(f"=== {idx}: {r['rule']} ===")
    for l in r['code_window'].splitlines():
        if not l.strip().startswith(('import ', 'package ')):
            print('  ', l[:100])
