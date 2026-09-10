# chatapp

پیام‌رسان امن بدون شماره تلفن/ایمیل — Android client + Cloudflare backend.

## وضعیت

| فاز | شرح | وضعیت |
|---|---|---|
| Phase 0 | تحقیق: SimpleX UI، libsignal، Cloudflare، ناسازگاری‌ها | ✅ انجام شد |
| Phase 0.5 | Crypto prototype با libsignal رسمی | 🔨 در حال اجرا |
| Phase 1+ | Cloudflare Workers / D1 / DO / R2 | ⏳ پس از تأیید prototype |

## Crypto

- **libsignal رسمی** — `org.signal:libsignal-client:0.102.1` از مخزن رسمی
  [build-artifacts.signal.org](https://build-artifacts.signal.org/libraries/maven/)
  (Maven Central برای نسخه‌های جدید libsignal به‌روز نیست)
- **Java 21+ لازم است** — bytecode کتابخانه با Java 21 کامپایل شده است
- پروتکل فعلی libsignal شامل PQXDH است (one-time Kyber-1024 prekey اجباری در PreKeyBundle)

## Prototype (Phase 0.5)

`prototype/` — JVM prototype که مدل پروژه را با API واقعی libsignal اثبات می‌کند:
identity per-device، SignedPreKey + KyberPreKey + OneTimePreKey، برقراری session،
encrypt/decrypt (هر دو مسیر PreKeySignalMessage و SignalMessage)،
persistence به‌صورت serialized bytes (شبیه‌ساز Room)، replay protection،
TOFU identity trust، و مصرف یک‌بارمصرف prekeyها.

```bash
./gradlew :prototype:test
```

## Build

- JDK 21 (Temurin)
- تست‌ها در GitHub Actions اجرا می‌شوند (`.github/workflows/ci.yml`)

## License

AGPL-3.0 — این پروژه به libsignal (AGPLv3) متصل است؛ کل اپ باید AGPLv3 منتشر شود.
