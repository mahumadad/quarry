"""Local-only positive, soft-404 and generic-login fixtures for Nuclei templates."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SECRETS = """SECRET_KEY=fixture-python-secret
DATABASE_URL=postgres://fixture:fixture@localhost/db
DB_PASSWORD=fixture-node-password
JWT_SECRET=fixture-jwt-secret
secret_key_base: fixture-rails-secret
APP_KEY=base64:fixture-laravel-key
MAIL_PASSWORD=fixture-mail-password
ConnectionStrings: Server=localhost;Password=fixture-dotnet-password;
PAYPAL_CLIENT_SECRET="fixture-paypal-secret"
"""

OPENAPI = """{"openapi":"3.0.0","swagger":"2.0","info":{"title":"fixture"},"paths":{},"html":"Swagger UI swagger-ui ReDoc redoc SwaggerUIBundle SwaggerModule"}"""
DEBUG = """TypeError: fixture
at Module._compile (node_modules/express/fixture.js:1:1)
Django Debug Toolbar djdt Django DEBUG = True You're seeing this error because you have DEBUG = True
Werkzeug Debugger The debugger caught an exception Traceback (most recent call last) console SECRET
Ignition Facade\\Ignition Spatie\\Ignition Stack trace Laravel exception
Developer Exception Page An unhandled exception occurred Stack Query Cookies Headers Routing Microsoft.AspNetCore System.Exception
"""


def response_for(path: str, body: bytes) -> tuple[int, str, str]:
    """Return status, content-type and deterministic non-secret fixture content."""
    if path in {"/graphql", "/api/graphql", "/_v/graphql"}:
        text = body.decode("utf-8", errors="replace")
        if text.startswith("["):
            return 200, "application/json", '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]'
        if "__schema" in text:
            return 200, "application/json", '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[{"name":"Query"}]}}}'
        return 400, "application/json", '{"errors":[{"message":"Did you mean __typename?"}]}'
    if (path.endswith(".js") or path.endswith(".js.map")) and not path.startswith("/_next/"):
        if path.endswith(".map"):
            return 200, "application/json", '{"sources":["app.ts"],"names":["fixture"],"mappings":"AAAA","sourcesContent":["const fixture = true;"]}'
        live = "sk_live_" + "a" * 24
        test = "sk_test_" + "b" * 24
        mp_live = "APP_USR-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        mp_test = "TEST-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        return 200, "application/javascript", f"const live='{live}'; const test='{test}'; const mp='{mp_live}'; const mt='{mp_test}'; {SECRETS}"
    if path in {"/.env", "/.env.local", "/.env.production", "/settings.py", "/config.py", "/instance/config.py", "/config/default.json", "/config/production.json", "/config.json", "/config/database.yml", "/config/secrets.yml", "/config/master.key", "/config/credentials.yml", "/appsettings.json", "/appsettings.Production.json", "/web.config", "/config/database.php"}:
        return 200, "text/plain", SECRETS
    if path.startswith("/rest/V1/"):
        return 200, "application/json", '[{"id":1,"code":"default","base_url":"http://fixture","locale":"en_US","base_currency_code":"USD"}]'
    if path.startswith("/api/catalog_system"):
        return 200, "application/json", '{"items":[{"productId":"1"}]}'
    if path == "/api/sessions":
        return 200, "application/json", '{"session":{"segments":{}}}'
    if path.startswith("/_v/segment"):
        return 200, "application/json", '{"segments":{"channel":"1"}}'
    if path.startswith("/api/io"):
        return 200, "application/json", '{"apps":[{"vendor":"fixture"}]}'
    if path.startswith("/api/v1/accounts") or path.startswith("/api/v2/accounts") or "transactions" in path:
        return 200, "application/json", '{"account_id":"fixture-account","transaction_id":"fixture-transaction","balance":0,"amount":0,"currency":"USD"}'
    if path.startswith("/actuator/health") or path == "/health":
        return 200, "application/json", '{"status":"UP","components":{"db":{"status":"UP","details":{}},"diskSpace":{"status":"UP"}}}'
    if path.endswith("/mappings"):
        return 200, "application/json", '{"contexts":{"app":{"mappings":{"dispatcherServlets":{"x":[{"predicate":"{GET /fixture}"}]}}}}}'
    if path.endswith("/env"):
        return 200, "application/json", '{"propertySources":[{"properties":{"password":{"value":"fixture"},"spring.datasource.url":{"value":"fixture"}}}]}'
    if path.startswith("/api/http/routers") or path == "/api/overview" or path.startswith("/dashboard"):
        return 200, "application/json", '{"routers":[{"rule":"Host(`fixture`)","entryPoints":["web"],"provider":"file","service":"fixture","status":"enabled","middlewares":[]}],"Traefik":true}'
    if path.startswith("/config_dump") or path.startswith("/clusters") or path.startswith("/server_info"):
        return 200, "text/plain", '{"configs":[],"dynamic_active_clusters":[],"static_resources":{"listeners":[]},"cluster":"fixture","server_info":{},"version_info":"fixture","upstream":true,"envoy":true}'
    if path in {"/services", "/routes"}:
        return 200, "application/json", '{"services":[],"routes":[],"data":[],"next":null,"tagline":"Welcome to kong","version":"fixture"}'
    if path == "/":
        return 200, "application/json", '{"tagline":"Welcome to kong","version":"fixture","services":[],"routes":[],"data":[]}'
    if path.startswith("/package") or path.endswith("yarn.lock") or "package-lock" in path:
        return 200, "application/json", '{"name":"fixture","version":"1.0.0","lockfileVersion":3,"dependencies":{},"devDependencies":{},"packages":{},"__metadata":{},"yarn lockfile":true}'
    if "flower" in path:
        return 200, "text/html", "Celery Flower celery@fixture active_queues workers tasks queues Flower"
    if "bull" in path or path in {"/queues", "/admin/queues"}:
        return 200, "text/html", "Bull Board BullMQ @bull-board Queues queue jobs"
    if path.startswith("/sidekiq"):
        return 200, "text/html", "Sidekiq sidekiq_version processed failed busy queues"
    if "horizon" in path:
        return 200, "text/html", 'Laravel Horizon "horizon" jobs queues workload failed'
    if path.startswith("/_next/"):
        return 200, "application/javascript", "self.__BUILD_MANIFEST={};self.__SSG_MANIFEST=new Set();self.__MIDDLEWARE_MANIFEST={};static/chunks sortedPages"
    if "__nuxt_devtools__" in path:
        return 200, "text/html", "Nuxt DevTools __NUXT_DEVTOOLS__ nuxt-devtools devtools client"
    if path.startswith("/rails/info") or path == "/rails/mailers":
        return 200, "text/html", "Rails version Ruby version Application root rails/info Routes match in priority Prefix Verb URI Pattern Controller#Action Action Mailer"
    if path in {"/admin", "/admin/", "/admin/login/", "/magento_admin", "/backend", "/admin/Site/FullCleanUp.aspx"}:
        return 200, "text/html", "Magento magento admin__login adminhtml magento-logo vtex VTEX vtexid vtex-id VTEX ID Django administration Log in | Django csrfmiddlewaretoken django-admin"
    if path.startswith("/__debug__") or path == "/silk/":
        return 200, "text/html", DEBUG + " Silk Requests"
    if path == "/console" or path in {"/debug", "/__express", "/nonexistent_route_12345", "/_ignition/health-check"}:
        status = 500 if path in {"/nonexistent_route_12345", "/debug", "/__express"} else 200
        return status, "text/html", DEBUG
    if any(token in path for token in ("docs", "swagger", "openapi", "redoc", "api-json")):
        return 200, "text/html", OPENAPI
    return 200, "text/html", "fixture unmatched route"


def make_server(mode: str = "positive") -> tuple[ThreadingHTTPServer, threading.Thread]:
    class Handler(BaseHTTPRequestHandler):
        def _respond(self):
            if mode == "negative":
                status, content_type, content = 200, "text/html", "<html>Not found but HTTP 200</html>"
            elif mode == "login":
                status, content_type, content = 200, "text/html", "<html><form><input type=password>Sign in</form></html>"
            else:
                length = int(self.headers.get("Content-Length", "0"))
                status, content_type, content = response_for(self.path, self.rfile.read(length))
            raw = content.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = _respond
        do_POST = _respond

        def log_message(self, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
