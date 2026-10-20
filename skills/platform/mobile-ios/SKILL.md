---
name: mobile-ios
description: >
  iOS application security testing for authorized engagements: IPA static
  analysis, keychain data review, URL scheme / universal link abuse, ATS
  (App Transport Security) exception abuse, jailbreak detection bypass.
  Keywords: iOS, IPA, keychain, URL scheme, universal link, ATS,
  jailbreak detection, Frida, objection, class-dump. Do NOT use for
  Android (see mobile-android), or for a backend API the app merely talks
  to — hand identified endpoints to standard web/API testing skills; this
  skill covers the client binary and on-device attack surface only.
metadata:
  type: platform
  phase: hunting
  tools: [frida, objection, class-dump, ideviceinstaller, mitmproxy, r2]
depends_on: [recon-asset-discovery]
feeds_into: [chain-analysis, api-testing]
chains_with: [mobile-android, exfiltration-via-ai]
---

## Signals
- `.ipa` file provided in scope, or app downloadable from App Store for an in-scope target.
- App registers custom URL schemes (`CFBundleURLTypes` in `Info.plist`) or universal links (`apple-app-site-association`).
- App makes API calls to an in-scope backend.

## Prerequisites
- Written authorization naming the specific app bundle ID in scope.
- Jailbroken iOS device (checkra1n/palera1n for compatible iOS versions) or a jailbroken simulator/corellium instance; `frida-server` running on-device.
- `objection`, `class-dump`/`class-dump-dyld`, `ideviceinstaller`, `plutil`, `mitmproxy`/Burp.

## Methodology

### 1. Static analysis — extract and inspect the IPA
```bash
unzip target.ipa -d target_ipa
plutil -convert xml1 -o - target_ipa/Payload/Target.app/Info.plist | grep -A3 "CFBundleURLSchemes\|NSAppTransportSecurity"
class-dump -H target_ipa/Payload/Target.app/Target -o headers/
# Look for hardcoded secrets/API keys in binary strings
strings target_ipa/Payload/Target.app/Target | grep -iE "api[_-]?key|secret|http://"
```

### 2. ATS exception review (plaintext HTTP / weak TLS allowed)
```bash
plutil -convert xml1 -o - target_ipa/Payload/Target.app/Info.plist | grep -B2 -A10 "NSAppTransportSecurity"
# NSAllowsArbitraryLoads=true or a domain exception with NSExceptionAllowsInsecureHTTPLoads=true is a finding
```

### 3. Install and connect for dynamic testing
```bash
ideviceinstaller -i target.ipa
frida-ps -Ua | grep -i target
objection -g com.target.app explore
```

### 4. Jailbreak detection bypass
```bash
objection -g com.target.app explore
ios jailbreak disable
# Or targeted Frida script hooking common checks (file existence, fork(), Cydia URL scheme)
frida -U -f com.target.app -l frida-scripts/ios-jailbreak-bypass.js --no-pause
```

### 5. Certificate pinning bypass (for Burp/mitmproxy interception)
```bash
objection -g com.target.app explore
ios sslpinning disable
# Or SSL Kill Switch 2 style universal bypass if objection's hooks don't cover custom pinning
```

### 6. URL scheme / universal link abuse
```bash
# Trigger a custom scheme directly to test for auth bypass, data leak, or injection
xcrun simctl openurl booted "targetapp://reset?token=injected"
# On a real device via SSH (jailbroken)
ssh root@<device-ip> "uiopen targetapp://admin/debug"
```

### 7. Keychain and local storage review
```bash
objection -g com.target.app explore
ios keychain dump
ios plist cat Info.plist
ios cookies get
# Direct filesystem access on jailbroken device
ssh root@<device-ip> "find /var/mobile/Containers/Data/Application -iname '*.sqlite' -path '*target*'"
```

### 8. Runtime class/method inspection and hooking
```bash
objection -g com.target.app explore
ios hooking list classes
ios hooking search methods isJailbroken
ios hooking watch class_method "TargetApp.AuthManager.validateToken:"
```

## Tooling
`Frida`+`frida-server`, `objection`, `class-dump`, `ideviceinstaller`, `libimobiledevice` suite, `mitmproxy`/Burp Suite, `r2` (radare2) for binary analysis.

## Validation Gate
- Keychain/local-storage findings must show actual extracted sensitive data (token, credential, PII), not just "keychain is accessible on a jailbroken device" (expected on any jailbroken device regardless of app).
- ATS exception findings must be confirmed as actually reachable/used in a real request flow, not just present in `Info.plist` but dead code.
- Capture exact `objection`/Frida output and the plist excerpt as evidence.

## Gotchas
- Jailbreak detection bypass results can be device/iOS-version specific — a script working on checkra1n/iOS 14 may not work on palera1n/iOS 16; verify the bypass actually holds before building further tests on top of it.
- App Store builds strip debug symbols and often harden against Frida (anti-debugging, `ptrace` self-attach) more than client-provided TestFlight/ad-hoc builds — confirm which build is in scope.
- `NSAllowsArbitraryLoads` findings should be weighed against whether the exception is scoped to a specific non-sensitive domain vs. global.
- Always test against a build/bundle ID explicitly confirmed in scope — App Store apps are live production software affecting real users; destructive dynamic testing should stay confined to test accounts.
