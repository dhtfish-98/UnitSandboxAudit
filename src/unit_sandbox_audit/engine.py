# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
"""Audit one service's ordered, supplied unit fragments and sandbox declarations."""
import re
import shlex
import posixpath
from .common import InputError, Report, mapping, sequence, string, logical_lines

BOOLEAN=('NoNewPrivileges','PrivateTmp','PrivateDevices','ProtectKernelTunables','ProtectKernelModules',
 'ProtectKernelLogs','ProtectControlGroups','RestrictSUIDSGID','LockPersonality','MemoryDenyWriteExecute')
LISTS={'CapabilityBoundingSet','AmbientCapabilities','RestrictAddressFamilies','SystemCallFilter','ReadWritePaths'}
KNOWN=set(BOOLEAN)|LISTS|{'User','Group','DynamicUser','ProtectSystem','ProtectHome','UMask','ExecStart','ExecStartPre','ExecStartPost','Type','WorkingDirectory','Restart','Description','Environment','EnvironmentFile','TimeoutStartSec','TimeoutStopSec'}
TRUE={'yes','true','1','on'};FALSE={'no','false','0','off'}
FAMILIES={'AF_UNIX','AF_INET','AF_INET6','AF_PACKET','AF_NETLINK'}
LIMITS=['Caller supplies authoritative fragment order, including selected drop-ins; this tool does not discover unit search paths, masks or inherited defaults.',
 'Static sandbox declarations only. Capability/syscall inversion and specifiers are OPEN; missing settings are OPEN. DynamicUser and sandbox availability/compatibility need a Linux host test.',
 'Policy prefers a restricted service. A finding does not imply that every restriction is appropriate for every service.']

def boolean(value,label):
    lower=value.lower()
    if lower in TRUE:return True
    if lower in FALSE:return False
    raise InputError('invalid boolean for '+label)

def analyze(snapshot):
    mapping(snapshot,'snapshot'); fragments=sequence(snapshot.get('fragments'),'fragments')
    report=Report('UnitSandboxAudit','One service, authoritative ordered fragments, sandbox and privilege declarations')
    values={};origins={};seen=set()
    for frag in fragments:
        mapping(frag,'fragment');name=string(frag.get('name'),'fragment.name');text=string(frag.get('text'),'fragment.text')
        if name in seen:raise InputError('duplicate fragment name')
        seen.add(name);section=None
        for number,raw in logical_lines(text):
            line=raw.strip();where=name+':'+str(number)
            if not line or line.startswith(('#',';')):continue
            if line.startswith('[') and line.endswith(']'):section=line[1:-1];continue
            if section!='Service':
                if section is None:report.add('syntax','OPEN',where,'Assignment outside a section')
                continue
            if '=' not in line:report.add('syntax','OPEN',where,'Unknown unit line');continue
            key,value=(s.strip() for s in line.split('=',1))
            if not re.fullmatch('[A-Za-z][A-Za-z0-9]*',key):raise InputError('invalid unit directive')
            if key not in KNOWN:report.add('directive','OPEN',where,'Directive outside implemented policy: '+key);continue
            origins[key]=where
            if key in LISTS:
                if not value:values[key]=[]
                else:
                    try:tokens=shlex.split(value)
                    except ValueError as exc:raise InputError(str(exc)) from exc
                    if value.startswith('~') or any('%' in x for x in tokens):report.add('list_semantics','OPEN',where,'Inverted/specifier list not evaluated')
                    values.setdefault(key,[]).extend(tokens)
            elif key.startswith('Exec'):
                if not value:values[key]=[]
                else:values.setdefault(key,[]).append(value)
            else:values[key]=value
    for key in BOOLEAN:
        if key not in values:report.add('sandbox','OPEN',key,'Missing explicit sandbox declaration');continue
        if not values[key]:report.add('sandbox','OPEN',origins[key],'Reset to implicit default');continue
        try:flag=boolean(values[key],key)
        except InputError:report.add('sandbox','OPEN',origins[key],'Unknown/version-dependent boolean');continue
        report.check('sandbox',flag,origins[key],key+'='+values[key])
    dynamic=None
    if values.get('DynamicUser'):
        try:dynamic=boolean(values['DynamicUser'],'DynamicUser')
        except InputError:report.add('identity','OPEN',origins['DynamicUser'],'Invalid DynamicUser value')
    user=values.get('User')
    if user:
        if '%' in user:report.add('identity','OPEN',origins['User'],'User specifier is unresolved')
        elif re.fullmatch(r'[0-9]+',user):
            if len(user)>64:report.add('identity','OPEN',origins['User'],'Numeric identity exceeds supported bound')
            else:
                uid=int(user)
                if uid>=2**32-1:report.add('identity','OPEN',origins['User'],'Numeric identity outside supported Linux UID range')
                else:report.check('identity',uid!=0,origins['User'],'Declared numeric service UID')
        elif re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,255}',user):report.check('identity',user!='root',origins['User'],'Declared service name; NSS resolution remains OPEN')
        else:report.add('identity','OPEN',origins['User'],'Unsupported service identity syntax')
    elif dynamic is True:report.add('identity','PASS',origins['DynamicUser'],'Dynamic non-root service identity requested')
    else:report.add('identity','OPEN','User','No resolved non-root identity declaration')
    for key,accepted in [('ProtectSystem',{'strict'}),('ProtectHome',{'yes','true','1','read-only','tmpfs'})]:
        if key in values:report.check('filesystem',values[key] in accepted,origins[key],key+'='+values[key])
        else:report.add('filesystem','OPEN',key,'Missing explicit filesystem restriction')
    for key in ('CapabilityBoundingSet','AmbientCapabilities'):
        if key not in values:report.add('capabilities','OPEN',key,'Implicit capabilities are not inferred');continue
        if any(x.startswith('~') for x in values[key]):continue
        dangerous={'CAP_SYS_ADMIN','CAP_SYS_PTRACE','CAP_DAC_OVERRIDE','CAP_DAC_READ_SEARCH','CAP_SETUID','CAP_SETGID','CAP_SYS_MODULE'}
        report.check('capabilities',not dangerous.intersection(values[key]),origins[key],key+' contains privileged capabilities')
        report.add('capability_scope','PASS' if not values[key] else 'OPEN',origins[key],'Empty set requested' if not values[key] else 'Non-empty set requires service justification')
    families=values.get('RestrictAddressFamilies')
    if families is None:report.add('address_families','OPEN','RestrictAddressFamilies','Unrestricted/implicit family list')
    elif any(x.startswith('~') for x in families):pass
    else:
        if set(families)-FAMILIES:report.add('address_families','OPEN',origins['RestrictAddressFamilies'],'Family outside supported explicit policy')
        report.check('address_families',not {'AF_PACKET','AF_NETLINK'}.intersection(families),origins['RestrictAddressFamilies'],'Raw packet/netlink family declarations')
        if not families:report.add('address_families','OPEN',origins['RestrictAddressFamilies'],'Empty assignment resets family filter')
    if 'SystemCallFilter' in values:report.add('syscall_filter','OPEN',origins['SystemCallFilter'],'Syscall group/inversion semantics are not evaluated')
    if not values.get('ExecStart'):report.add('execution','OPEN','ExecStart','No start command in supplied fragments')
    for key in ('ExecStart','ExecStartPre','ExecStartPost'):
        for value in values.get(key,[]):
            # systemd extracts/unquotes/C-unescapes the first word before applying
            # privilege prefixes, and supports legacy ';' command separators.
            # This profile deliberately declines that unimplemented lexical scope.
            if any(c in value for c in ('\\', '"', "'", ';')):
                report.add('exec_syntax','OPEN',origins[key],'Quoted/escaped/semicolon command syntax is outside the selected lexical profile')
                continue
            prefix=re.match(r'^[-@:+!|]*',value)[0]
            report.check('exec_privileges','+' not in prefix and '!' not in prefix,origins[key],'Privilege-changing command prefix')
    if 'UMask' in values:
        mask=values['UMask']
        if re.fullmatch(r'[0-7]{1,4}',mask):report.check('umask',(int(mask,8)&0o077)==0o077,origins['UMask'],'Expected service private-file mask 0077')
        else:report.add('umask','OPEN',origins['UMask'],'Symbolic/invalid mask not evaluated')
    else:report.add('umask','OPEN','UMask','No explicit private-file mask')
    for value in values.get('ReadWritePaths',[]):
        path=value.lstrip('-+');prefix=value[:len(value)-len(path)]
        if '%' in path or len(prefix)>2 or len(set(prefix))!=len(prefix) or not path.startswith('/'):
            report.add('writable_paths','OPEN',origins['ReadWritePaths'],'Unsupported/specifier writable path declaration');continue
        normalized=posixpath.normpath(path)
        report.check('writable_paths',set(normalized)!={'/'},origins['ReadWritePaths'],'Broad writable root escape after lexical normalization; symlinks are not resolved')
    if not fragments:report.add('coverage','OPEN','fragments','No unit fragments')
    return report.finish(LIMITS)
