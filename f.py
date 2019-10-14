import json

d = json.load(open('j.json'))

out = open('magic.ktrace', 'w')
for x in d:
    print(f"#[id = {x['id']}]", file=out)
    print(f"syscall {x['name']} {'{'}", file=out)
    print("    ret: num", file=out)
    print("}\n", file=out)
