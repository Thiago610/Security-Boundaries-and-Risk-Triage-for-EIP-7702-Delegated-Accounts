"""Interpretable triage on normalized, offline authorization observations."""
WEIGHTS = {'universal':2, 'unknown_code':2, 'code_mismatch':4,
           'burst':2, 'uninitialized':2}

def score(event, disabled=()):
    reasons = [k for k in WEIGHTS if k not in disabled and event.get(k,False)]
    return sum(WEIGHTS[k] for k in reasons), reasons

def inspect(event, threshold=4):
    value,reasons = score(event)
    return {'id':event.get('id'),'score':value,'alert':value>=threshold,
            'reasons':reasons,'interpretation':'risk indicator, not proof of compromise'}
