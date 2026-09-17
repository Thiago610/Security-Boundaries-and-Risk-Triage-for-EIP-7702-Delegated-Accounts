"""Deterministic synthetic stress tests; labels are sampled before features."""
from pathlib import Path
import csv, json, random, statistics
from .protocol import World,Account,sign
from .detector import WEIGHTS,score
from eth_keys import keys

FEATURES=list(WEIGHTS)
# Independent conditional Bernoulli generator, not a labeling rule.
PROBS={'benign':[.12,.12,.01,.08,.08], 'attack':[.55,.70,.55,.65,.50],
       'benign_shift':[.35,.30,.03,.35,.20], 'attack_shift':[.20,.30,.25,.20,.25]}

def writecsv(path,rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader();w.writerows(rows)

def metrics(labels,predictions):
    tp=sum(y and p for y,p in zip(labels,predictions)); fp=sum(not y and p for y,p in zip(labels,predictions))
    fn=sum(y and not p for y,p in zip(labels,predictions));tn=len(labels)-tp-fp-fn
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    return dict(precision=precision,recall=recall,f1=2*precision*recall/(precision+recall) if precision+recall else 0,
                fpr=fp/(fp+tn) if fp+tn else 0,tp=tp,fp=fp,fn=fn,tn=tn)

def run(output, seeds=20, events=2000):
    if seeds < 1 or events < 1:
        raise ValueError('seeds and events must be positive')
    OUT=Path(output)
    OUT.mkdir(parents=True,exist_ok=True)
    runs=[]; curves=[]; examples=[]
    variants={'Universal only':None,'Unknown code only':None,'Full score':(),
              'No chain feature':('universal',),'No code features':('unknown_code','code_mismatch'),
              'No context features':('burst','uninitialized')}
    for shifted in (False,True):
        domain='Shifted' if shifted else 'Nominal'
        for seed in range(seeds):
            rng=random.Random(seed+1000*shifted); observations=[]
            for i in range(events):
                label=rng.random()<.15
                probs=PROBS[('attack' if label else 'benign')+('_shift' if shifted else '')]
                event=dict(zip(FEATURES,[rng.random()<p for p in probs]))
                event.update(id=f'{domain}-{seed}-{i}',label=int(label))
                observations.append(event)
            if seed==0:examples.extend(observations)
            labels=[e['label'] for e in observations]
            for name,disabled in variants.items():
                predictions=[e['universal'] if name=='Universal only' else e['unknown_code'] if name=='Unknown code only' else score(e,disabled)[0]>=4 for e in observations]
                runs.append(dict(domain=domain,seed=seed,method=name,**metrics(labels,predictions)))
            for threshold in range(0,14):
                curves.append(dict(domain=domain,seed=seed,threshold=threshold,**metrics(labels,[score(e)[0]>=threshold for e in observations])))
    writecsv(OUT/'detector_runs.csv',runs);writecsv(OUT/'threshold_runs.csv',curves)
    with (OUT/'synthetic_observations.jsonl').open('w') as f:
        for e in examples:f.write(json.dumps(e)+'\n')
    summaries=[]
    for domain in ('Nominal','Shifted'):
        for name in variants:
            r=[x for x in runs if x['domain']==domain and x['method']==name]
            row=dict(domain=domain,method=name)
            for m in ('precision','recall','f1','fpr'):
                vals=[x[m] for x in r];row[m]=statistics.mean(vals);row[m+'_sd']=statistics.stdev(vals) if len(vals)>1 else 0
            summaries.append(row)
    writecsv(OUT/'detector_summary.csv',summaries)
    # Signed authorization grid: chain binding x target chain x nonce x code x receipt.
    key=(1).to_bytes(32,'big'); user=keys.PrivateKey(key).public_key.to_address();sponsor='0x'+'22'*20;target='0x'+'33'*20
    grid=[]
    for signed_chain in (0,1):
        for chain in (1,31337):
            for nonce in (0,1):
                for code_type,code in [('empty',b''),('delegated',bytes.fromhex('ef0100')+bytes.fromhex('44'*20)),('ordinary',b'\x60\x00')]:
                    for revert in (False,True):
                        world=World(chain,{user:Account(nonce=nonce,code=code,balance=100)})
                        def execute(states):
                            states[user].balance=0
                            if revert:raise RuntimeError('controlled revert')
                        result=world.process(sponsor,[sign(key,signed_chain,target,0)],execute)
                        reason=result['outcomes'][0]['reason']
                        expected=(signed_chain in (0,chain) and nonce==0 and code_type!='ordinary')
                        assert (reason=='accepted')==expected
                        assert world.accounts[user].balance==(100 if revert else 0)
                        if expected:assert len(world.accounts[user].code)==23
                        grid.append(dict(signed_chain=signed_chain,chain=chain,initial_nonce=nonce,code_type=code_type,revert=revert,accepted=int(reason=='accepted'),reason=reason))
    writecsv(OUT/'protocol_grid.csv',grid)
    metadata={'dataset':'synthetic','seeds':seeds,'events_per_seed_per_domain':events,
              'observations':2*seeds*events,'attack_prevalence':.15,'probabilities':PROBS,
              'weights':WEIGHTS,'threshold':4,'protocol_cases':len(grid)}
    (OUT/'metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    return metadata
