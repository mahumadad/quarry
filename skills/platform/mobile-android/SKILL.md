---
name: mobile-android
description: >
  Android application security testing for authorized engagements: APK
  decompilation and static analysis, certificate pinning bypass, exported
  content provider abuse, intent-based attack surface. Keywords: Android,
  APK, decompile, smali, Frida, certificate pinning, content provider,
  intent, deep link, jadx, mobsf. Do NOT use for iOS (see mobile-ios), or
  for a backend API the app merely talks to — once an endpoint is
  identified, hand it to standard web/API testing skills; this skill
  covers the client binary and on-device attack surface only.
metadata:
  type: platform
  phase: hunting
  tools: [jadx, apktool, frida, mobsf, adb, objection, drozer]
depends_on: [recon-asset-discovery]
feeds_into: [chain-analysis, api-testing]
chains_with: [mobile-ios, exfiltration-via-ai]
---

## Signals
- `.apk` file provided in scope, or app downloadable from Play Store/APK mirror for an in-scope target.
- App makes API calls to an in-scope backend (identify via static strings / dynamic traffic capture).
- App exports activities/providers/services (`exported="true"` in manifest) or registers deep link schemes.

## Prerequisites
- Written authorization naming the specific app package/bundle ID in scope.
- Rooted Android device or emulator (AVD with root, or Magisk-rooted physical device/Genymotion), `adb` access.
- `jadx`, `apktool`, `frida` + `frida-server` on device, `objection`, `MobSF` (for automated static baseline), `drozer`.

## Methodology

### 1. Static analysis — decompile and read the manifest
```bash
apktool d target.apk -o target_apktool
jadx -d target_jadx target.apk
cat target_apktool/AndroidManifest.xml | grep -i "exported\|permission\|scheme"
# Automated baseline (SAST + known weaknesses)
# upload target.apk to a local MobSF instance: http://localhost:8000
```

### 2. Identify exported attack surface
```bash
grep -A2 'exported="true"' target_apktool/AndroidManifest.xml
# List installed app's exported components live on device
drozer console connect
dz> run app.package.attacksurface com.target.app
dz> run app.activity.info -a com.target.app
dz> run app.provider.info -a com.target.app
```

### 3. Content provider abuse (SQL injection / path traversal / data leak)
```bash
dz> run app.provider.query content://com.target.app.provider/users --vertical
dz> run scanner.provider.injection -a com.target.app
dz> run scanner.provider.traversal -a com.target.app
# Direct query via adb
adb shell content query --uri content://com.target.app.provider/users
```

### 4. Intent / deep link abuse
```bash
# Launch an exported activity directly, bypassing intended flow (e.g. auth bypass)
adb shell am start -n com.target.app/.AdminActivity
# Deep link fuzzing
adb shell am start -W -a android.intent.action.VIEW -d "targetapp://reset-password?token=../../admin" com.target.app
```

### 5. Certificate pinning bypass (needed before intercepting HTTPS traffic)
```bash
frida-server &   # on rooted device
objection -g com.target.app explore
# Inside objection
android sslpinning disable
# Or a universal Frida script
frida -U -f com.target.app -l frida-scripts/android-ssl-bypass.js --no-pause
```

### 6. Dynamic traffic capture through Burp
```bash
# Set device proxy to Burp, install Burp CA, then run with pinning disabled
adb shell settings put global http_proxy 10.10.10.5:8080
# After pinning bypass, traffic flows through Burp for normal web/API testing
```

### 7. Runtime manipulation / root & debug detection bypass
```bash
objection -g com.target.app explore
android root disable
android hooking list classes
android hooking search methods com.target.app isRootDetected
```

### 8. Local data storage review
```bash
adb shell run-as com.target.app ls -la /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml
adb shell run-as com.target.app sqlite3 /data/data/com.target.app/databases/app.db ".dump"
```

## Tooling
`jadx`, `apktool`, `Frida`+`frida-server`, `objection`, `drozer`, `MobSF`, `adb`, `Burp Suite`.

## Validation Gate
- Content provider/intent findings must show an actual data leak or state change achieved from an unprivileged app context (e.g. a second test app invoking the exported component), not just "exported=true in manifest."
- Pinning bypass success must be confirmed by observing decrypted traffic in Burp, not just "the Frida script ran without error."
- Capture the exact `adb`/`drozer`/`objection` command and output as evidence.

## Gotchas
- `exported="true"` on an activity/provider is sometimes intentional (e.g. share intents, deep links meant to be public) — confirm actual sensitive-data exposure before flagging.
- Root detection and SSL pinning often layer multiple checks (native code, root cloaking checks) — a single bypass script may not defeat all of them; check `logcat` for crash/kill signals.
- Testing against the Play Store production build vs. a client-provided debug build can yield very different results (ProGuard/R8 obfuscation, debuggable flag) — confirm which build is in scope.
- Modifying `adb shell settings put global http_proxy` persists after testing — reset it when done.
