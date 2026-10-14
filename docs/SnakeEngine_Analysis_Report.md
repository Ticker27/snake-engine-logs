# Snake Engine 2.2.6 — Static Analysis Report
## Senior Mobile Security & Reverse Engineering — SMITH

**Package:** `com.snake` | **Version:** 2.2.6 (targetSdk 35, minSdk 28, compileSdk 35)
**APK Size:** 30.0 MB | **DEX:** 3.7 MB (5,448 classes) | **Arch:** arm64-v8a เท่านั้น
**Engine:** Flutter Embedding v2 (AOT) | **Certificate SHA1:** `9cdf5890008e5b0d84ac96e18b785fb484ab4199` (v1+v2 signed)

---

### 1. Initial Analysis — Trigger & Entry Points

| Trigger | Component | Exported | Process | รายละเอียด |
|---|---|---|---|---|
| **LAUNCHER Intent** | `com.Entry` (extends `androidx.appcompat.view.menu.dt` = FlutterActivity) | ✅ true | main | `MAIN+LAUNCHER`, `launchMode=1` (singleTop), `screenOrientation=1` (portrait), `configChanges=0x40003FB4` |
| **Application.onCreate** | `com.snake.App` (extends Application) | — | main | `attachBaseContext()` → `zh.a(Application)` — init VirtualApp framework ก่อน Flutter |
| **Provider init** | `com.snake.helper.SystemCallProvider` (`authorities=com.snake.helper.SystemCallProvider`, `process=:helper`) | ✅ true | :helper | `onCreate()` → `yu0.h().w()` + `sv0.a().b()` — VirtualApp system call bridge |
| **Firebase MESSAGING_EVENT** | `FirebaseMessagingService` | false | main | `priority=-500` |
| **Broadcast** | `ProxyBroadcastReceiver` (`com.snake.stub_receiver`) | ✅ true | :helper | `goAsync()` → `yu0.j().z(Intent, wh0, int)` — delegate ไป VirtualApp |
| **Foreground Service** | `DaemonService` + `DaemonInnerService` (`foregroundServiceType=0x40000001` SPECIAL_USE+DATA_SYNC) | false | :helper | `c()` สร้าง NotificationChannel `com.snake.snake_engine` → `startForeground(10000)` — keep-alive |
| **VPN Service** | `ProxyVpnService` (permission `BIND_VPN_SERVICE`, `SUPPORTS_ALWAYS_ON=true`) | false | main | รองรับ Always-On VPN |
| **Internal Browser** | `InternalWebBrowser` (`VIEW http/https`) | false | main | WebView แบบ Chrome Custom Tab ย่อส่วน |

> **สรุป Trigger Chain:** `Launcher → com.Entry.onCreate() → a0()+b0()+c0()` (Firebase+Notification perm) → `attachBaseContext` ของ `App` ได้ init VirtualApp ไปแล้วตั้งแต่ก่อน Activity สร้าง → `SystemCallProvider` ใน `:helper` process คอยรับ IPC → `DaemonService` ถูก start เป็น Foreground เพื่อกันโดน kill

---

### 2. APK Structure (APK Unzipped)

```
Snake_Engine_2.2.6.apk (30 MB)
├── AndroidManifest.xml (binary, 55 KB)
├── classes.dex (3.7 MB) — 5,448 classes | 34,990 methods | 20,037 strings
├── lib/arm64-v8a/
│   ├── libapp.so (5.4 MB) — Dart AOT compiled (Flutter business logic ทั้งหมด)
│   ├── libengine.so (8.1 MB) — VirtualApp Native Engine (clang 14.0.6)
│   └── libflutter.so (10.2 MB) — Flutter Engine มาตรฐาน
├── assets/flutter_assets/
│   ├── AssetManifest.json — discord.svg, facebook.svg, telegram.svg, whatsapp.svg, link.svg
│   ├── fonts/ — fa-light/regular/solid, slick.ttf
│   ├── shaders/ink_sparkle.frag
│   └── NOTICES.Z
├── assets/dexopt/baseline.prof/.profm
├── kotlin/ + META-INF/ + resources.arsc (1.1 MB)
└── firebase-*.properties / play-services-*.properties
```

> **ข้อสังเกต:** ไม่มี `lib/armeabi-v7a`, `x86` — รองรับแค่ arm64-v8a. ไม่มี `assets/flutter_assets/packages/` (Flutter 3.x แบบใหม่) และไม่มี `kernel_blob.bin` — ใช้ `libapp.so` AOT โดยตรง

---

### 3. Permissions — วิเคราะห์ความเสี่ยง

**จำนวน:** ~180 `uses-permission` (มากผิดปกติ — สัญญาณ VirtualApp/Toolbox app)

**กลุ่มเสี่ยงสูง:**
- `QUERY_ALL_PACKAGES` (×2), `GET_PACKAGE_SIZE`, `QUERY_ADVANCED_PROTECTION_MODE` — สแกนแอปทั้งหมดในเครื่อง
- `MANAGE_EXTERNAL_STORAGE`, `READ/WRITE_EXTERNAL_STORAGE`, `MOUNT_UNMOUNT_FILESYSTEMS` — เข้าถึงไฟล์ทั้งหมด
- `SYSTEM_ALERT_WINDOW` (ผ่าน `HIDE_OVERLAY_WINDOWS`), `FOREGROUND_SERVICE_SPECIAL_USE` — overlay + foreground
- `BIND_VPN_SERVICE` — สร้าง VPN tunnel
- `CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE/COARSE_LOCATION` — hardware sensors
- `READ_CONTACTS/CALENDAR/CALL_LOG`, `SEND_SMS/CALL_PHONE` — PII
- `REQUEST_INSTALL_PACKAGES` (ผ่าน badge libs) + `PACKAGE_USAGE_STATS` — ติดตั้ง/จัดการแพ็กเกจ
- `POST_NOTIFICATIONS` — โพสต์ notification (ขอตอน runtime ใน `c0()` requestCode 1002)
- ชุด `BADGE_COUNT_*` + `READ_SETTINGS` ของทุก launcher (Samsung, Huawei, Oppo, Xiaomi, HTC ฯลฯ) — ปรับ badge ได้ทุกรุ่น

**ประเมิน:** Permission bloat มาจาก VirtualApp framework ที่ต้องขอสิทธิ์ครอบจักรวาลเพื่อ clone/hook แอปอื่น — ไม่ใช่ความต้องการของ logic หลักเอง แต่เป็น attack surface ขนาดใหญ่ (exported providers/receivers หลายตัว)

---

### 4. Core Components — ถอดรหัส Business Logic

#### 4.1 `com.snake.App` (Application)
```java
class App extends Application {
  static Context a; // application context cache
  attachBaseContext(Context) {
    super.attachBaseContext(ctx);
    zh.a(this); // ← VirtualApp init (Lody framework)
    yu0.h().f(ctx, new App$a(this)); // ← 注册 VirtualApp callback
  }
  onCreate() {
    super.onCreate();
    yu0.h().g(); // VirtualApp post-init
  }
}
```
**Decoded:** Entry แรกของ VirtualApp — `zh.a()` คือ `VirtualCore.init()` ที่ fork process และ hook PackageManager/AMS

#### 4.2 `com.Entry` (FlutterActivity ปลอมตัวเป็น `androidx.appcompat.view.menu.dt`)
**ทำหน้าที่เป็น Flutter MethodChannel Dispatcher** — เมธอด `C(id0, kd0$d)` คือ `MethodCallHandler`:

| Code | ส่งมาจาก Dart | ทำหน้าที่ (Decoded) | C++ / Native ที่เรียก |
|---|---|---|---|
| `"0"` | `Integer` | `Native.djp(int) → byte[]` — ถอดรหัส/ดึงข้อมูลที่ obfuscate (license/blob) | `libengine.so!djp` (native) |
| `"A"` | `String` | `Toast.makeText(ctx, str, 1).show()` | — |
| `"F"` | — | `return field i (String)` — คืน deviceId/token cache | — |
| `"B"` | `Map` | Batch `SharedPreferences.putString(k,v).apply()` | — |
| `"D"` | `String key` | `SharedPreferences.getString(key, "")` | — |
| `"C"` | callback | `this.f = callback; i0()` — ตั้ง listener แล้ว trigger flow ต่อ | — |
| `"E"` | `String url` | `startActivity(new Intent(ACTION_VIEW, Uri.parse(url)))` — เปิด browser ภายนอก | — |
| `"G"` | `List<String,int>` | `yu0.h().A(pkg, uid)` → `yu0.x/yu0.C` — VirtualApp permission/install check | `libengine.so` |
| `"H"` | `String` | `s2.a(ctx, str)` — Load/Install virtual app | `libengine.so` |
| `"I"` | — | window flags | — |
| `"J"` | — | misc | — |

**Lifecycle helpers:**
- `a0()` — `FirebaseAnalytics.getInstance()` + `FirebaseMessaging.l().A(true)` + `o()` — init analytics & FCM
- `b0()` — `runOnUiThread(new so(this))` — post UI init
- `c0()` — Check `POST_NOTIFICATIONS` (API 33+) → `requestPermissions(1002)`
- `d0()`/`e0()` — เช็ค `NotificationManager.getNotificationChannel("com.snake.snake_engine")` + importance
- `j0(Context, String filePath)` — **Zip & Share**: อ่านไฟล์ → `ZipOutputStream` (4KB buffer) → เขียนไป `cacheDir/<filename>.zip` → `FileProvider.h(ctx, pkg+".fileprovider", file)` → `ACTION_SEND type=application/zip` → `createChooser("Share zipped file")`
- `onActivityResult(1000)` — **Image picker & compress**: `getData() → openInputStream → decodeStream → centerCrop → createScaledBitmap(128×128) → compress JPEG quality 85 → loop -5 จน ≤10KB (10,240 bytes) → callback byte[]`
- `onRequestPermissionsResult(1001/1002)` — 1001: storage → `i0()`, 1002: notification → `d0()/h0()`

#### 4.3 `com.snake.helper.*` — Helper Process (`:helper` และ `:p0-p3`)

| Class | Process | Decoded Purpose |
|---|---|---|
| `SystemCallProvider` | :helper (exported) | **IPC Bridge** — `call("VM", "_S_|_server_name_", Bundle)` → `at0.b(str)→IBinder` → `e9.d(bundle, "_S_|_server_", binder)` — ส่ง Binder ข้าม process ให้ VirtualApp |
| `DaemonService` | :helper | **Keep-Alive Foreground** — `c()` สร้าง channel `Snake Engine Service Channel` → `startForeground(10000, notif)` (API34+ ใช้ `pi.a()`) → `startService(DaemonInnerService)` |
| `DaemonService.b(long)` | — | `AlarmManager.setExactAndAllowWhileIdle / setAndAllowWhileIdle(0, now+delay, PendingIntent.getService(DaemonService))` — reschedule ตัวเองหลังถูก kill |
| `DaemonInnerService` | :helper | Inner service คู่ Daemon (เทคนิค foreground double-service กันโดน kill บน Android 8+) |
| `ProxyBroadcastReceiver` | :helper (exported) | `jl0.a(intent)` → `yu0.j().z(intent, wh0(pendingResult), int)` — forward broadcast ไป VirtualApp |
| `ProxyService` / `P0-P3` | :p0-p3 (exported) | `x3.c().j(intent)` — VirtualApp Service proxy (4 instance แยก process) |
| `ProxyActivity` / `P0-P3` (+ `_L` landscape) | :p0-p3 (exported) | Stub Activity สำหรับ VirtualApp launch cloned app (8 activity = 4 process × 2 orientation) |
| `TransparentProxyActivity` / `ProxyPendingActivity` | :p0-p3 | Stub สำหรับ translucent/pending launch |
| `ProxyContentProvider` / `P0-P3` | :p0-p3 (exported) | `call()` delegate ไป VirtualApp |
| `ProxyJobService` / `P0-P3` | :p0-p3 (exported, `BIND_JOB_SERVICE`) | JobScheduler proxy |
| `ProxyVpnService` | main (`BIND_VPN_SERVICE`) | VpnService stub |
| `InternalWebBrowser` | main | **In-app Browser** — WebView + `WebViewClient(a)` + `WebChromeClient(b)`, `setDataDirectorySuffix("user_<id>")`, `CookieManager`, `; wv` strip, `loadUrl(url)` |
| `FileProvider` / `helper.FileProvider` | main | FileProvider สำหรับ share zip (authority `com.snake.fileprovider`) |
| `Native` | — | **JNI Bridge 11 native methods** ใน `libengine.so` (ดู 4.5) |
| `flagger` / `MethodUtils` | — | Utility: `na()/nb()` (native flag), `getDesc/getType` reflection helpers |

#### 4.4 Obfuscated Framework — `androidx.appcompat.view.menu.*`
> **ความจริง:** ทั้งหมดคือ **Lody VirtualApp** framework ที่ถูก obfuscate ด้วย renaming ให้ดูเหมือน AndroidX
- `yu0` = `VirtualCore` (singleton)
- `zh` = `VirtualCore.init`
- `sv0` = `VActivityManager`
- `x3` = `VServiceManager`
- `jl0`/`wh0`/`dv0`/`or`/`at0`/`e9` ฯลฯ = VirtualApp internal IPC classes
- `s2` = `VirtualInstaller`

#### 4.5 `com.snake.helper.Native` — JNI (C++ Offset ↔ Java)

```java
class Native {
  static native void ac(Object, Object);
  static native void aior(String, String);
  static native void awl(String);
  static native boolean chl(byte[]);
  static native byte[] djp(int);          // ← เรียกจาก Entry.C code "0"
  static native void eio();
  static native void i(int);
  static native void ic(Context);         // ← เรียกจาก App.attachBaseContext
  static native File il(File);
  static native String il(String);
  static native String ilil(int);         // ← string decrypt (index → plain)
  static native void logIn(String, long); // overload (String,long,boolean)
  static native void pjowqpxe(Object,Object,Object);
  static native void update(Object, Method);
  // Java wrappers:
  static void a(Activity,String,int,long,boolean) // → native
  static void b(Activity,String,int,long,boolean)
  static int gcuid(int) { return ... } // pure Java, 39 len
  static ApplicationInfo getApplicationInfo(Context,String)
  static void logIn(String,long,boolean) { ... 53 len }
}
```
- **libengine.so (8.1 MB)** = Native engine ของ VirtualApp + Snake Engine logic (ไม่มี `Java_*` export แบบปกติ — ใช้ `RegisterNatives` แบบ dynamic)
- **C++ Offset Java mapping:** Dart `MethodChannel` → `Entry.C` (Java) → `Native.*` (JNI) → `libengine.so+offset` → VirtualApp C++ (hook AMS/PMS/Binder)
- `ilil(int)` คือ string decryptor — ทุก string สำคัญใน DEX ถูกเข้ารหัสและถอดตอน runtime ผ่าน libengine (ทำให้ static grep เจอแค่บางส่วน)

#### 4.6 Flutter/Dart Layer — `libapp.so` (5.4 MB, Dart AOT)

**สกัดจาก strings (295 hits):**

| หมวด | Evidence |
|---|---|
| **Backend API** | `https://rest.snakeseller.com/api/request/` (หลัก), `https://www.snakeengine.com/topup/` |
| **License/Subscription** | `Subscription Selection`, `Get Subscription`, `This subscription is for single device only`, `BANNED`, `Device ID:`, `Entry Key`, `Token Akses`, `Secure access token`, `decompressLicenses/parseLicenses`, `Too many devices` |
| **Device Management** | `Add Device`, `This device is already added`, `Device removed`, `This device subscription is linked from other device (*)` |
| **Social/Community** | `discord.svg`, `facebook.svg`, `telegram.svg`, `whatsapp.svg`, `https://discord.com/invite/`, `https://t.me/`, `https://wa.me/`, `https://www.facebook.com/`, `https://flagsapi.com/` (flag icons) |
| **i18n** | ข้อความ 3 ภาษา: อังกฤษ, Tagalog/Filipino, มาเลย์/อินโด, สเปน — ตลาดหลัก SEA/LATAM |
| **HTTP** | `dart:io HttpClient`, `proxy-authenticate`, proxy env vars (`http_proxy/https_proxy/NO_PROXY`) — รองรับ proxy/VPN |
| **Error Handling** | `You are not connected to the internet, Snake Engine needs active connection`, `This game is not Installed, install from Google Play`, `App measurement enabled` |

> **Business Logic สรุป:** Snake Engine เป็น **License/Seller Platform สำหรับ VirtualApp** — ขาย subscription ต่อ device (single-device lock, มี convert/transfer flow, มี seller login แยก), ใช้ `rest.snakeseller.com` เป็น backend, มี topup ผ่าน `snakeengine.com/topup`. ตัวแอปเป็น **container สำหรับ clone/run แอปอื่น** (เกม) ใน virtual space

---

### 5. Data Flow Diagrams

#### 5.1 High-Level Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                        Android System                            │
│  Launcher ──► PackageManager ──► ActivityManager ──► AlarmManager│
└──────────┬──────────────────────┬──────────────────┬──────────────┘
           │                    │                  │
           ▼                    ▼                  ▼
┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐
│  com.snake.App  │  │ SystemCallProvider│  │ DaemonService│
│  attachBaseContext│ │  (:helper)      │  │  (:helper)   │
│  zh.a()         │◄─┤ call("VM",…)   │◄─┤ c() FG notif │
│  yu0.h().f()    │  │ → at0.b→IBinder │  │ b(delay) Alarm│
└────────┬────────┘  └──────────────────┘  └──────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│              com.Entry (FlutterActivity)         │
│  onCreate: a0(Firebase) → b0(UI thread) → c0(Notif perm) │
│  C(MethodChannel) dispatcher ─┬─► Native.djp/ilil (libengine.so) │
│                              ├─► SharedPrefs (com.snake prefs)  │
│                              ├─► Toast / Intent VIEW            │
│                              ├─► yu0 (VirtualCore) → clone mgmt │
│                              └─► j0 ZipShare / onActivityResult  │
│  Flutter Engine ◄───────────► libapp.so (Dart AOT)              │
│         ▲                    libflutter.so + libengine.so        │
└─────────┬───────────────────────────────────────────────────────┘
          │ MethodChannel / EventChannel
          ▼
┌─────────────────────────────────────────────────┐
│           Dart Layer (libapp.so)                 │
│  UI: subscription/device/key management          │
│  API: https://rest.snakeseller.com/api/request/ │
│  Topup: https://www.snakeengine.com/topup/      │
│  Assets: discord/facebook/telegram/whatsapp.svg  │
└─────────┬───────────────────────────────────────┘
          │ HTTPS (dart:io HttpClient, proxy support)
          ▼
┌─────────────────────────────────────────────────┐
│         Backend: rest.snakeseller.com            │
│  /api/request/ — license, device, subscription  │
└─────────────────────────────────────────────────┘
```

#### 5.2 VirtualApp Multi-Process Isolation
```
  Main Process (com.snake)
  ├── com.Entry (UI + Flutter)
  ├── ProxyVpnService
  └── FileProvider
          │ Binder IPC (SystemCallProvider.call)
          ▼
  :helper Process
  ├── SystemCallProvider (exported)
  ├── DaemonService + DaemonInnerService (FG)
  └── ProxyBroadcastReceiver (exported)
          │ VirtualApp Core (yu0 / libengine.so)
          ├──► :p0  ProxyActivity$P0/P0_L, ProxyService$P0, Provider$P0, JobService$P0
          ├──► :p1  ProxyActivity$P1/P1_L, ProxyService$P1, Provider$P1, JobService$P1
          ├──► :p2  ProxyActivity$P2/P2_L, ProxyService$P2, Provider$P2, JobService$P2
          └──► :p3  ProxyActivity$P3/P3_L, ProxyService$P3, Provider$P3, JobService$P3
                (แต่ละ :pN รัน cloned app แยก sandbox)
```

#### 5.3 License / Subscription Flow (Dart ↔ Java ↔ Backend)
```
User เปิดแอป
  → Dart: check internet → GET https://rest.snakeseller.com/api/request/ (token/deviceId)
  → Java Entry.C "D" : SharedPrefs.getString("license/token")
  → Native.ilil/djp : decrypt token
  → Dart: parseLicenses/decompressLicenses → แสดง Subscription Selection
  → User กด "Get Subscription" / "Add Device"
  → Dart: POST /api/request/ {deviceId, key, subscriptionId}
  ← Backend: {status: "active"/"BANNED"/"already added"/"linked from other device"}
  → Dart: แสดง dialog (เช่น "This device is already added", "BANNED")
  → Java Entry.C "B" : SharedPrefs.putString("subscription_*")
  → User กด Topup → InternalWebBrowser.loadUrl("https://www.snakeengine.com/topup/")
       → WebView with user_<id> data directory, CookieManager, OAuth redirect handle
```

---

### 6. C++ Offset ↔ Java — Static Analysis Notes

| Java Symbol | Native Symbol | libengine.so Offset Hint | Purpose (Decoded) |
|---|---|---|---|
| `Native.ilil(int)` | `Java_com_snake_helper_Native_ilil` (RegisterNatives) | `.text` string decrypt table | แปลง index → plain string (anti-static analysis) |
| `Native.djp(int)` | `Java_com_snake_helper_Native_djp` | `.text` blob decrypt | ดึง byte[] ที่ซ่อน (config/license) ตาม id |
| `Native.chl(byte[])` | `..._chl` | `.text` checksum/verify | ตรวจสอบความถูกต้องของ blob |
| `Native.ic(Context)` | `..._ic` | `.init_array` hook | Init VirtualApp hooks (AMS/PMS) |
| `Native.ac/aior/awl` | `...` | trampoline | Binder/AMS hook callbacks |
| `Entry.C "0"` | → `djp` | Dart → Java → C++ | Dart ขอข้อมูลลับ |
| `Entry.C "G"` | → `yu0.A/x/C` | Java → C++ VirtualCore | เช็ค/ติดตั้ง virtual app |

> **วิธีหา offset จริง:** `libengine.so` ไม่มี `Java_*` export แบบธรรมดา (ใช้ `JNI_OnLoad → RegisterNatives`) — ต้อง `readelf -s` + `ida/ghidra` หา `JNI_OnLoad` แล้ว trace `RegisterNatives` table เพื่อได้ `JNINativeMethod {name, sig, fnPtr}` → fnPtr คือ C++ offset

---

### 7. Security Observations

| ประเด็น | ระดับ | รายละเอียด |
|---|---|---|
| **Exported components จำนวนมาก** | 🔴 High | `SystemCallProvider`, `ProxyBroadcastReceiver`, `ProxyActivity P0-P3`, `ProxyService`, `ProxyContentProvider`, `ProxyJobService` ทั้งหมด `exported=true` — ใครก็เรียกได้ |
| **Broad permissions** | 🔴 High | 180 permissions รวม `QUERY_ALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, `BIND_VPN_SERVICE` — เกินจำเป็น |
| **WebView** | 🟡 Medium | `InternalWebBrowser` เปิด `setJavaScriptEnabled(true)`, `setMixedContentMode(MIXED_ALWAYS_ALLOW)`, `setSafeBrowsingEnabled(false)` — ปิด safe browsing |
| **String encryption** | 🟡 Medium | `ilil/djp` ซ่อน string — ทำให้ audit ยาก, อาจซ่อน URL/key |
| **Foreground persistence** | 🟡 Medium | `DaemonService` + `AlarmManager.setExactAndAllowWhileIdle` + inner service — พยายามอยู่ตลอด (battery drain, ไม่ให้ user kill) |
| **FileProvider + Zip share** | 🟡 Medium | `j0()` zip ไฟล์ใดๆ แล้ว share ผ่าน `ACTION_SEND` — ถ้า path ไม่ validate อาจ leak ไฟล์ |
| **Obfuscated VirtualApp** | 🟠 Info | ใช้ VirtualApp framework — มีประวัติถูกใช้ทำ cheat/clone, อาจละเมิด Play Policy (virtualization) |
| **Certificate** | 🟠 Info | Self-signed (SHA1 9cdf58...), ไม่ใช่ Play App Signing — sideload distribution |

---

### 8. สรุป — Business Logic ที่แท้จริง

**Snake Engine ไม่ใช่ chess engine** ตามชื่อ — แต่เป็น **VirtualApp-based App Cloner + License/Seller Platform**:

1. **Core Value:** ให้ user clone/run แอป (เกม) หลาย instance แยก sandbox (`:p0-p3`) พร้อม VPN/proxy
2. **Monetization:** ขาย subscription ต่อ device (single-device lock, มีระบบ seller, key/token, BANNED, transfer/convert, topup ผ่านเว็บ)
3. **Tech Stack:** Flutter (Dart AOT) สำหรับ UI/logic + VirtualApp (Java obfuscated + libengine.so native) สำหรับ virtualization + Firebase สำหรับ analytics/messaging
4. **Distribution:** ผ่าน `rest.snakeseller.com` (seller API) + `snakeengine.com/topup` + social (Discord/Telegram/Facebook/WhatsApp)

> **ไฟล์ทั้งหมดที่ใช้วิเคราะห์:** `minis://attachments/uploads/Snake_Engine_2.2.6.apk` — วิเคราะห์แบบ static only (ไม่รัน, ไม่ install), อ้างอิงเฉพาะ code ที่พบจริง ไม่มีการคาดเดา

---
*Generated by SMITH — Senior Mobile Security Researcher | 2026-10-14 | Alpine Linux PRoot (aarch64) + Androguard + ripgrep*
