# chatapp

پیام‌رسان امن بدون شماره تلفن/ایمیل — Android client + Cloudflare backend.

## وضعیت

| فاز | شرح | وضعیت |
|---|---|---|
| Phase 0 | تحقیق: SimpleX UI، libsignal، Cloudflare، ناسازگاری‌ها | ✅ انجام شد |
| Phase 0.5-A | Crypto prototype روی JVM با libsignal رسمی (۸/۸ تست) | ✅ سبز در CI |
| Phase 0.5-B | Android: SQLCipher store + AndroidKeyStore، تست instrumented روی emulator | ✅ سبز در CI |
| Phase 1+ | Cloudflare Workers / D1 / DO / R2 | ⏳ نیازمند تأیید |

## Crypto

- **libsignal رسمی** — `org.signal:libsignal-android:0.102.1` از مخزن رسمی
  [build-artifacts.signal.org](https://build-artifacts.signal.org/libraries/maven/)
  (Maven Central برای نسخه‌های جدید libsignal به‌روز نیست)
- **Java 21 / Kotlin ≥ 2.2** لازم است (bytecode و metadata کتابخانه)
- Prootکل فعلی libsignal شامل PQXDH است — one-time Kyber-1024 prekey اجباری در PreKeyBundle
- `coreLibraryDesugaring` برای libsignal-android فعال است (الزام AAR metadata)
- AAR metadata: libsignal-android 0.102.1 → minCompileSdk=34؛ sqlcipher-android ≥4.18 → minCompileSdk=37 (به همین دلیل 4.17.0 پین شد)

## ساختار

```
prototype/   — Phase 0.5-A: JVM prototype (Store با serialized bytes = شبیه‌ساز Room)
android/     — Phase 0.5-B: library module
  crypto/DatabaseKeyManager.kt       — passphrase تصادفی + wrap با AndroidKeyStore (AES-GCM, non-exportable)
  crypto/SqlCipherProtocolStore.kt   — پیاده‌سازی کامل SignalProtocolStore روی SQLCipher
  androidTest/                       — تست instrumented روی emulator (CI)
```

## چیزی که تست‌ها اثبات می‌کنند

- identity per-device، SignedPreKey + KyberPreKey + OneTimePreKey، برقراری session (PQXDH)
- encrypt/decrypt هر دو مسیر (PreKeySignalMessage → SignalMessage) و گذار درست TYPE ها
- replay protection (DuplicateMessageException) و TOFU identity trust (UntrustedIdentityException)
- مصرف one-time prekeyها بعد از decrypt
- **persistence کامل بعد از restart**: بستن و باز کردن دیتابیس + unwrap passphrase از Keystore
- فایل دیتابیس روی دیسک **SQLite plaintext نیست** (SQLCipher فعال)
- identical بودن behavior بین JVM prototype و Android instrumented tests

## Build

- JDK 21 (Temurin) — `./gradlew :prototype:test` و `./gradlew :android:connectedAndroidTest`
- تست‌ها در GitHub Actions اجرا می‌شوند (`.github/workflows/ci.yml`)
- محلی برای اندروید نیاز به Android SDK است؛ compileSdk 35, minSdk 26

## License

AGPL-3.0 — این پروژه به libsignal (AGPLv3) متصل است؛ کل اپ باید AGPLv3 منتشر شود.
