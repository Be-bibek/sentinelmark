import json

out_path = r'd:\flutter_main\Bibek\sentinelmark\frontend\recovered_page.tsx.txt'
with open(r'C:\Users\Bibek\.gemini\antigravity-ide\brain\87cbfb42-93c8-441b-89ce-13c29a4d2aec\.system_generated\logs\transcript_full.jsonl', encoding='utf-8') as f:
    for line in f:
        if 'bg-white/[0.01] border-white/5' in line:
            data = json.loads(line)
            # Find the string containing it
            def find_str(obj):
                if isinstance(obj, dict):
                    for v in obj.values():
                        res = find_str(v)
                        if res: return res
                elif isinstance(obj, list):
                    for v in obj:
                        res = find_str(v)
                        if res: return res
                elif isinstance(obj, str):
                    if 'bg-white/[0.01] border-white/5' in obj:
                        return obj
                return None
            found = find_str(data)
            if found:
                with open(out_path, 'a', encoding='utf-8') as out:
                    out.write(found)
                    out.write("\n\n---\n\n")
                print("Found!")
