package com.frida.sslbypass;

import android.util.Log;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

/**
 * Universal SSL / certificate pinning bypass.
 * Java/Xposed port of the Frida script: hooks OkHttp's CertificatePinner,
 * the standard javax.net.ssl stack, Conscrypt, and TrustKit.
 *
 * Target packages are set in res/values/arrays.xml (xposed_scope).
 */
public class SSLPinningBypass implements IXposedHookLoadPackage {

    private static final String TAG = "SSLPinningBypass";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        // handleLoadPackage fires for every app in scope; lpparam.packageName
        // tells us which one, matching the Frida script's "attach to this app" model.
        log("Loaded in: " + lpparam.packageName);

        hookOkHttpCertificatePinner(lpparam);
        hookStandardTrustManager(lpparam);
        hookHostnameVerifier(lpparam);
        hookConscrypt(lpparam);
        hookTrustKit(lpparam);
    }

    // =========================================================
    // 1. BYPASS OKHTTP3 CERTIFICATE PINNER
    // =========================================================
    private void hookOkHttpCertificatePinner(XC_LoadPackage.LoadPackageParam lpparam) {
        // check(String, List<Certificate>)
        try {
            findAndHookMethod(
                    "okhttp3.CertificatePinner",
                    lpparam.classLoader,
                    "check",
                    String.class,
                    java.util.List.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("OkHttp Pinning bypassed (check/List) for: " + param.args[0]);
                            param.setResult(null);
                        }
                    }
            );
            log("OkHttp CertificatePinner.check(String, List) hooked.");
        } catch (Throwable t) {
            log("check(String, List) not found: " + t);
        }

        // check(String, Certificate...)
        try {
            findAndHookMethod(
                    "okhttp3.CertificatePinner",
                    lpparam.classLoader,
                    "check",
                    String.class,
                    Certificate_ARRAY_CLASS_NAME(),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("OkHttp Pinning bypassed (check/Certificate[]) for: " + param.args[0]);
                            param.setResult(null);
                        }
                    }
            );
            log("OkHttp CertificatePinner.check(String, Certificate[]) hooked.");
        } catch (Throwable t) {
            log("check(String, Certificate[]) not found: " + t);
        }

        // check$okhttp(String, Function0) - newer OkHttp internal variant
        try {
            findAndHookMethod(
                    "okhttp3.CertificatePinner",
                    lpparam.classLoader,
                    "check$okhttp",
                    String.class,
                    "kotlin.jvm.functions.Function0",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("OkHttp Pinning bypassed (check$okhttp) for: " + param.args[0]);
                            param.setResult(null);
                        }
                    }
            );
            log("OkHttp CertificatePinner.check$okhttp hooked.");
        } catch (Throwable t) {
            log("check$okhttp not found: " + t);
        }

        // findMatchingPins(String) -> empty list, belt-and-braces
        try {
            findAndHookMethod(
                    "okhttp3.CertificatePinner",
                    lpparam.classLoader,
                    "findMatchingPins",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("findMatchingPins bypassed for: " + param.args[0]);
                            param.setResult(Collections.emptyList());
                        }
                    }
            );
            log("OkHttp CertificatePinner.findMatchingPins hooked.");
        } catch (Throwable t) {
            log("findMatchingPins not found: " + t);
        }
    }

    // helper so we don't need a compile-time import just for the array class name
    private static String Certificate_ARRAY_CLASS_NAME() {
        return "[Ljava.security.cert.Certificate;";
    }

    // =========================================================
    // 2. BYPASS STANDARD ANDROID TRUST MANAGERS (SSLContext.init)
    // =========================================================
    private void hookStandardTrustManager(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            findAndHookMethod(
                    SSLContext.class.getName(),
                    lpparam.classLoader,
                    "init",
                    KeyManager[].class,
                    TrustManager[].class,
                    SecureRandom.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("Intercepted SSLContext.init(), injecting trust-all TrustManager.");
                            param.args[1] = new TrustManager[]{ new TrustAllTrustManager() };
                        }
                    }
            );
            log("Standard X509TrustManager / SSLContext.init hooked.");
        } catch (Throwable t) {
            log("Failed to hook standard TrustManager: " + t);
        }
    }

    private static class TrustAllTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) { }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) { }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    // =========================================================
    // 3. BYPASS HOSTNAME VERIFIER
    // =========================================================
    private void hookHostnameVerifier(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            findAndHookMethod(
                    HttpsURLConnection.class.getName(),
                    lpparam.classLoader,
                    "setDefaultHostnameVerifier",
                    HostnameVerifier.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("setDefaultHostnameVerifier() call intercepted, forcing trust-all verifier.");
                            param.args[0] = new TrustAllHostnameVerifier();
                        }
                    }
            );

            // Also make sure anything that already has a verifier instance
            // gets a trust-all result from verify() directly.
            findAndHookMethod(
                    HostnameVerifier.class.getName(),
                    lpparam.classLoader,
                    "verify",
                    String.class,
                    SSLSession.class,
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            log("HostnameVerifier.verify() bypassed for: " + param.args[0]);
                            return true;
                        }
                    }
            );
            log("HostnameVerifier hooked.");
        } catch (Throwable t) {
            log("Failed to hook HostnameVerifier: " + t);
        }
    }

    private static class TrustAllHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            log("HostnameVerifier bypassed for: " + hostname);
            return true;
        }
    }

    // =========================================================
    // 4. BYPASS CONSCRYPT (used by many React Native / Facebook-family apps)
    // =========================================================
    private void hookConscrypt(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            findAndHookMethod(
                    "com.android.org.conscrypt.Platform",
                    lpparam.classLoader,
                    "checkServerTrusted",
                    X509Certificate[].class,
                    String.class,
                    java.net.Socket.class,
                    boolean.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("Conscrypt TrustManager bypassed.");
                            param.setResult(null);
                        }
                    }
            );
            log("Conscrypt hooked.");
        } catch (Throwable t) {
            log("Conscrypt not found: " + t);
        }
    }

    // =========================================================
    // 5. BYPASS TRUSTKIT (React Native / Cordova)
    // =========================================================
    private void hookTrustKit(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            findAndHookMethod(
                    "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                    lpparam.classLoader,
                    "verify",
                    String.class,
                    SSLSession.class,
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) {
                            return true;
                        }
                    }
            );
            log("TrustKit hooked.");
        } catch (Throwable t) {
            log("TrustKit not found: " + t);
        }
    }

    private static void log(String msg) {
        Log.d(TAG, msg);
        XposedBridge.log(TAG + ": " + msg);
    }
}
