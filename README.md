# SSL Pinning Bypass — LSPosed/Xposed module

Java/Xposed port of a Frida universal SSL-pinning bypass script. Hooks:

- OkHttp `CertificatePinner` (`check`, `check$okhttp`, `findMatchingPins`)
- Standard `javax.net.ssl` stack (`SSLContext.init` → trust-all `TrustManager`)
- `HostnameVerifier` (both `setDefaultHostnameVerifier` and any verifier's `verify()`)
- Conscrypt `Platform.checkServerTrusted`
- TrustKit's `OkHostnameVerifier`

## 1. Set the target app(s)

Edit `app/src/main/res/values/arrays.xml` and list the package name(s) you
want this module to hook, one `<item>` per app:

```xml
<array name="xposed_scope">
    <item>com.fluxicash.app</item>
</array>
```

Commit that change before building, or edit the scope later from inside the
LSPosed Manager app on-device (LSPosed lets you tick/untick apps in its UI
regardless of what's in this file).

## 2. Build on GitHub (no local Android Studio needed)

This repo includes a GitHub Actions workflow
(`.github/workflows/build.yml`) that builds a debug APK on every push to
`main`/`master`, or on demand:

1. Push this repo to GitHub.
2. Go to the **Actions** tab → **Build Xposed Module APK** → **Run workflow**
   (or just push a commit).
3. When the run finishes, open it and download the **sslpinningbypass-debug-apk**
   artifact — that's the installable APK.

The debug build is unsigned-but-debug-signed by Gradle automatically, which
is fine for sideloading onto a device you control.

## 3. Install and enable

1. Install the downloaded APK on the device (`adb install app-debug.apk`,
   or copy it over and open it).
2. Open **LSPosed Manager** → **Modules** → enable **SSL Pinning Bypass**.
3. Confirm the target app (from step 1) is checked in the module's scope.
4. Reboot, or force-stop and relaunch the target app.

## 4. Verify it's working

```
adb logcat | grep SSLPinningBypass
```

You should see lines like:

```
D SSLPinningBypass: OkHttp Pinning bypassed (check/List) for: api.fluxicash.com
```

when the target app makes an HTTPS call. If nothing prints, the app's pinning
implementation isn't one of the five hooked here — grab the crash/exception
stack trace from logcat and the exact class/method in it, since that tells
you which class to add a hook for.

## Notes

- This only works through LSPosed/EdXposed (needs root or a Zygisk-based
  LSPosed install, e.g. via Magisk). It is not a standalone Frida gadget
  setup — if you specifically need the no-root gadget-injection route,
  that's a different packaging process (`libfrida-gadget.so` baked into the
  target APK), not this module.
- `xposedminversion` is set to `82` (a recent Xposed API level); lower it
  in `AndroidManifest.xml` if your LSPosed build reports an incompatibility.
