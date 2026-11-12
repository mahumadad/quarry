from django.conf import settings
from django.contrib import admin
from django.http import HttpResponse, JsonResponse
from django.urls import include, path


def health(request):
    return JsonResponse({"status": "ok", "mode": "vulnerable" if settings.VULNERABLE else "secure"})


def environment(request):
    if not settings.VULNERABLE:
        return HttpResponse("Not found", status=404)
    return HttpResponse("SECRET_KEY=lab-only-django-secret\nDATABASE_URL=sqlite:///lab.sqlite3\n", content_type="text/plain")


urlpatterns = [path("api/v1/health", health), path(".env", environment)]
if settings.VULNERABLE:
    urlpatterns += [path("admin/", admin.site.urls), path("__debug__/", include("debug_toolbar.urls"))]
