#!/bin/bash
# Validates the supported Sigma detection subset directly against supplied Sysmon JSONL.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INCIDENT="${1:-$ROOT/incident_sysmon.jsonl}"
CLEAN="${2:-$ROOT/clean_sysmon.jsonl}"
python3 - "$ROOT" "$INCIDENT" "$CLEAN" <<'PY'
import json, pathlib, re, sys
try:
    import yaml
except ImportError:
    sys.exit('ERROR: PyYAML is required: python3 -m pip install pyyaml')
root, incident, clean = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
files = [root/'sigma_powershell_msbuild_lolbin.yml', root/'sigma_msbuild_network_c2.yml']
field_map = {'Image':'image','ParentImage':'parent_image','DestinationHostname':'dst_hostname',
             'DestinationIp':'dst_ip','DestinationPort':'dst_port','Initiated':'initiated',
             'CommandLine':'cmdline','EventID':'event_id'}
category_event = {'process_creation':1,'network_connection':3}
def test_term(record, key, patterns):
    field, *mods = key.split('|')
    if field not in field_map: raise ValueError(f'Unsupported Sigma field: {field}')
    if len(mods)>1 or (mods and mods[0] not in ('endswith','startswith','contains')):
        raise ValueError(f'Unsupported modifier: {key}')
    value = record.get(field_map[field])
    if value is None: return False
    candidates = patterns if isinstance(patterns,list) else [patterns]
    for pattern in candidates:
        a,b=str(value).lower(),str(pattern).lower()
        if not mods and a==b or mods==['endswith'] and a.endswith(b) or mods==['startswith'] and a.startswith(b) or mods==['contains'] and b in a:
            return True
    return False
def match(rule,record):
    category=rule['logsource']['category']
    if record.get('event_id')!=category_event[category]:return False
    detection=rule['detection']
    selections={k:all(test_term(record,field,pats) for field,pats in v.items())
                for k,v in detection.items() if k!='condition'}
    tokens=re.findall(r'\b(?:and|or|not|[A-Za-z_][A-Za-z_0-9]*)\b|[()]',detection['condition'],re.I)
    expr=[]
    for token in tokens:
        if token.lower() in ('and','or','not') or token in ('(',')'):expr.append(token.lower())
        elif token in selections:expr.append(str(selections[token]))
        else:raise ValueError(f'Unsupported condition token: {token}')
    # Evaluating only a strict grammar of boolean literals and operators (no user-provided Python).
    def parse(tokens):
        pos=0
        def atom():
            nonlocal pos
            if pos>=len(tokens):raise ValueError('Incomplete condition')
            t=tokens[pos];pos+=1
            if t=='not':return ('not',atom())
            if t=='(':
                node=orexpr()
                if pos>=len(tokens) or tokens[pos]!=')':raise ValueError('Missing )')
                pos+=1;return node
            if t in ('True','False'):return t=='True'
            raise ValueError('Invalid condition')
        def andexpr():
            nonlocal pos
            node=atom()
            while pos<len(tokens) and tokens[pos]=='and':pos+=1;node=('and',node,atom())
            return node
        def orexpr():
            nonlocal pos
            node=andexpr()
            while pos<len(tokens) and tokens[pos]=='or':pos+=1;node=('or',node,andexpr())
            return node
        result=orexpr()
        if pos!=len(tokens):raise ValueError('Unexpected condition tokens')
        return result
    def evaluate(node):
        if isinstance(node,bool):return node
        if node[0]=='not':return not evaluate(node[1])
        if node[0]=='and':return evaluate(node[1]) and evaluate(node[2])
        return evaluate(node[1]) or evaluate(node[2])
    return evaluate(parse(expr))
def read_events(path):
    if not path.is_file():raise FileNotFoundError(f'Missing sample: {path}')
    events=[]
    for n,line in enumerate(path.read_text(encoding='utf-8').splitlines(),1):
        if line.strip():
            try:events.append(json.loads(line))
            except json.JSONDecodeError as e:raise ValueError(f'{path}:{n}: {e}')
    return events
for path in files:
    if not path.is_file():raise FileNotFoundError(f'Missing Sigma rule: {path}')
    rule=yaml.safe_load(path.read_text(encoding='utf-8'))
    print(f'\n=== {path.name} ===')
    for label,sample in [('incident',incident),('clean',clean)]:
        events=read_events(sample)
        matched=[x for x in events if match(rule,x)]
        total=len(events); rate=100*len(matched)/total if total else 0
        verdict=('PASS' if matched else 'FAIL') if label=='incident' else ('PASS' if rate<0.1 else 'REVIEW')
        print(f'  [{sample.name}]\n  Total events: {total}\n  Matches: {len(matched)}\n  {"False positive rate" if label=="clean" else "Match rate"}: {rate:.3f}%\n  Verdict: {verdict}')
        if label=='clean' and matched:
            print('  Clean matches (potential false positives):')
            for x in matched:
                print(f'    {x.get("ts")} host={x.get("host")} pid={x.get("pid")} image={x.get("image")} parent={x.get("parent_image")} dst={x.get("dst_hostname") or x.get("dst_ip")}')
PY
