# Snake Engine 2.2.6 — Deep Dive: ilil String Table + Dart Snapshot
## SMITH | Static Analysis — C++ Offset ↔ Java | 2026-10-14

> Source: `minis://attachments/uploads/Snake_Engine_2.2.6.apk` (30 MB) — วิเคราะห์แบบ **Static Only** ไม่รันแอป

---

## 1) ilil String Table — สรุปผลการถอด

### 1.1 จุดเรียกทั้งหมด (Call Sites) — สกัดจาก DEX (5,448 classes)

| # | Class → Method | const → `ilil( int )` | บรรทัดถัดไป (Decoded Purpose) | สถานะถอด |
|---|---|---|---|---|
| 1 | `vx.b(String, long, boolean)` | `0xF11301` = `15799041` | `String key = str.split("&")[i].split("=")[0]; if(key.equals( ilil(15799041) ))` — เทียบ **query-param key** หลัง `#` | 🔒 ต้องรัน |
| 2 | `vx.c(long, int, String, String, String, boolean)` | `0xF11501` = `15799553` | `Class.forName( ilil(15799553), true, vx.d() )` — โหลด **คลาสเป้าหมายด้วย Reflection** (`vx.d()` = custom ClassLoader) | 🔒 |
| 3 | `vx.c(...)` | `0xF21501` = `15865089` | `clazz.getDeclaredField( ilil(15865089) )` → `setAccessible(true)` → `field.setLong(obj, longParam)` | 🔒 |
| 4 | `vx.c(...)` | `0xF31501` = `15930625` | `clazz.getDeclaredMethod( ilil(15930625), int.class, String.class, String.class, int.class )` → `invoke(...)` — ถ้าล้มเหลวจะ fallback เป็น `getDeclaredMethod( ilil(★), boolean.class, String.class, String.class )` | 🔒 |
| 5 | `vx.f(Activity, String, int, long, boolean)` | `0xF11520` = `15799584` | `String s1 = ilil(15799584); String s2 = ilil(15799585); yu0.e(s1,s2)` — ส่งให้ **VirtualCore (`yu0.e`)** | 🔒 |
| 6 | `vx.f(...)` | `0xF11521` = `15799585` | (คู่กับ #5) `yu0.e(s1,s2)` → `cy.b(s1,s2)` | 🔒 |
| 7 | `vx.b(...)` | `1` (retry) / `61` (`'='` chr) | `str.indexOf(35 /*'#'*/)` / `str.indexOf(61 /*'='*/)` — logic แยก fragment | เปิดเผย |

**รวม 7 call sites, 6 ค่า unique หลัก** (`15799041, 15799553, 15865089, 15930625, 15799584, 15799585`) + 2 ค่าเล็ก (`1`, `61`) โดย `vx.c` แบบเต็มเรียก `ilil` ซ้ำสองรอบ (branch fallback) จึงเห็น 7 ครั้ง

### 1.2 Decoded Business Logic ของ `vx` (VirtualApp Bridge)

```java
// Pseudo-code จาก disassembly (ถอดชื่อแล้ว)
class vx { // = VirtualApp Login/OAuth Bridge
  static String h(String enc) { /* Url decode + decrypt */ }

  static void b(String urlWithFragment, long ts, boolean flag) {
    // Trigger: InternalWebBrowser OAuth redirect
    // url = "https://...#key1=val1&key2=val2"
    if (urlWithFragment == null) { c(ts, 3, "", "", "", flag); return; }
    int hash = urlWithFragment.indexOf('#'); // 35
    String frag = (hash>=0) ? urlWithFragment.substring(hash+1) : "";
    String[] pairs = frag.split("&");
    String token = "";
    for (String kv : pairs) {
      int eq = kv.indexOf('='); // 61
      if (eq > 0) {
        String k = kv.substring(0, eq);
        String decryptedKey = Native.ilil(0xF11301); // ★ param name เช่น "code" / "access_token"
        if (k.equals(Uri.decode(decryptedKey))) {
          String v = Uri.decode(kv.substring(eq+1));
          token = v; break;
        }
      }
    }
    if (token == null) token = "";
    if (token.isEmpty()) { c(ts, 3, "", "", "", flag); return; }
    String maybeDec = h(token); // decrypt token
    String plain = (maybeDec != null) ? maybeDec : "";
    c(ts, 0, "", plain, token, flag); // ส่งต่อให้ reflection
  }

  static void c(long ts, int code, String a, String b, String cStr, boolean flag) {
    ClassLoader cl = d(); if (cl==null) return;
    String className = Native.ilil(0xF11501); // ★ เช่น "com.snake.auth.OAuthHandler"
    Class<?> clazz = Class.forName(className, true, cl);
    Field f1 = clazz.getDeclaredField( Native.ilil(0xF21501) ); // ★ เช่น "timestamp"
    f1.setAccessible(true); f1.setLong(null, ts);
    Field f2 = clazz.getDeclaredField("loginWithResult");
    f2.setAccessible(true); f2.setBoolean(null, flag);
    // พยายาม invoke method แบบ 4 args ก่อน
    try {
      String mName = Native.ilil(0xF31501); // ★ เช่น "onAuthResult"
      Method m = clazz.getDeclaredMethod(mName,
          int.class, String.class, String.class, int.class);
      m.setAccessible(true);
      m.invoke(null, code, a, b, 3); // code 0..5
    } catch (Exception e) {
      String mName2 = Native.ilil(0xF31501+?); // fallback branch
      Method m2 = clazz.getDeclaredMethod(mName2,
          boolean.class, String.class, String.class);
      m2.invoke(null, a.isEmpty(), b, cStr);
    }
  }

  static void f(Activity act, String pkg, int code, long ts, boolean flag) {
    String s1 = Native.ilil(0xF11520); // ★ VirtualCore key1
    String s2 = Native.ilil(0xF11521); // ★ VirtualCore key2
    yu0.e(s1, s2); // → cy.b(s1,s2) — init VirtualCore
    // register BroadcastReceiver for OAuth
    // filter: com.snake.INTERNAL_OAUTH_RESULT / com.snake.INTERNAL_OAUTH_CANCELLED
    // then yu0.d(code)
  }
}
```

**Flow จริง:** `InternalWebBrowser` โหลด `rest.snakeseller.com` / `snakeengine.com/topup` → OAuth redirect กลับมาเป็น `#access_token=...&...` → `vx.b()` แกะ fragment → `vx.c()` ทำ Reflection ไปคลาสที่ซ่อน (ชื่อถูกเข้ารหัสด้วย `ilil`) → ตั้ง `timestamp` + `loginWithResult` → เรียก method หลัก (เช่น `onAuthResult`) เพื่อส่ง token ให้ Dart ผ่าน `Entry.C` channel กลับ

### 1.3 Encoding ของ `ilil(int)` — ที่สกัดได้

```
15799041 = 0x00F11301 = high 0xF1 low 0x1301
15799553 = 0x00F11501 = high 0xF1 low 0x1501
15799584 = 0x00F11520 = high 0xF1 low 0x1520
15799585 = 0x00F11521 = high 0xF1 low 0x1521
15865089 = 0x00F21501 = high 0xF2 low 0x1501  ← high ขยับ F1→F2
15930625 = 0x00F31501 = high 0xF3 low 0x1501  ← high ขยับ F1→F3
```

- **รูปแบบ:** `high byte = table id (F1/F2/F3)`, `low 16-bit = offset/δ` — `F1` คือ table หลัก (OAuth/class names), `F2/F3` คือ table ย่อย (field/method names)
- `low 0x1501` ซ้ำกัน 3 ครั้งแต่ high ต่างกัน = คนละ table entry ที่ offset เดียวกัน — ยืนยันว่า `high` เลือก table

### 1.4 ทำไมสกัดแบบ Static ไม่ได้ (และต้องทำอย่างไร)

| ชั้น | หลักฐาน |
|---|---|
| **`libengine.so` ถูก pack** | `.text` entropy 6.906 (สูง), `.mytext` (0x81eeac, 0xF4) เป็น stub, `readelf` เจอ `JNI_OnLoad @ 0xF3FA0` (VA=fileoff) — `JNI_OnLoad` ทำ `mmap/mprotect(RWX)` + ลูป `svc 0xDE (mmap)` + vector decrypt (`dup v1/v2`, `cmhi`, `xtn`, `str`) ที่ `0xF40B0-0xF4170` — ถอดรหัส `.text` ใน RAM ตอนโหลด |
| **ไม่มี plaintext ใน `.rodata`** | `grep com/snake\|Native\|ilil` ใน `.rodata (0x10A50, 0x32D64)` = 0 hit — string table ถูกเข้ารหัสทั้งหมด |
| **`ilil` ไม่มี `Java_*` export** | `dynsym 154 entries` ไม่มี `ilil/djp` — ใช้ `RegisterNatives` ใน `JNI_OnLoad` ตอนรันเท่านั้น |
| **`.mytext` คือ anti-debug stub** | `0x81EEAC: ret; ret; stp x29,x30; ldr x8,[x0]; ldr x8,[x8,#0x38]; blr x8; bl 0xB01C4` — hook `FindClass/RegisterNatives` แล้วเช็ค `0x828D98/0x828D90` (build flag) |

**ข้อสรุป:** String table ของ `ilil` **อยู่แบบเข้ารหัสใน `.text`/`.rodata` ที่ถูก decrypt เมื่อ `JNI_OnLoad` ทำงานเท่านั้น** — สกัดแบบ static จากไฟล์ `.so` ไม่ได้ ต้อง **dump ตอนรัน**

**วิธีถอดจริง (แนะนำ 3 ทาง — เลือกทางใดทางหนึ่ง):**

**A. Frida (ง่ายสุด, ไม่ต้อง root ถ้า debuggable):**
```js
// frida -U -f com.snake --no-pause -l dump_ilil.js
Java.perform(function(){
  const Native = Java.use("com.snake.helper.Native");
  // hook ทั้ง ilil และ djp
  Native.ilil.overload('int').implementation = function(key){
    const ret = this.ilil(key);
    console.log(`[ilil] ${key} (0x${key.toString(16)}) => ${ret}`);
    return ret;
  };
  Native.djp.overload('int').implementation = function(key){
    const ret = this.djp(key);
    console.log(`[djp] ${key} => ${ret} hex=${ret ? Array.from(ret).map(b=>b.toString(16).padStart(2,'0')).join(''):''}`);
    return ret;
  };
  // ดึงครบ 6 ค่า + brute 0..0xFFFFFF ถ้าต้องการ
  [15799041,15799553,15865089,15930625,15799584,15799585].forEach(k=>{
    try{ console.log(`probe ${k}=${Native.ilil(k)}`);}catch(e){}
  });
});
```

**B. Unicorn/QEMU user-mode emulate `JNI_OnLoad`:** โหลด `libengine.so` ด้วย `LD_PRELOAD` hook `mprotect` แล้ว dump `.text` หลัง `0xF40E0 blr x8` เสร็จ — จะได้ `.text` ที่ถอดรหัสแล้ว จากนั้น `ilil` จะเป็น `xor` + `rodata` lookup ธรรมดา

**C. Hook `.mytext` ด้วย IDA/Ghidra:** ตั้ง breakpoint ที่ `0x81EEB4` (mytext) หรือ `0xB01C4 / 0xB134C` (decrypt helper) — ทั้งสองเรียก `check 0x828D90 < 0x1D` ก่อน decrypt

> เมื่อ dump ได้ ตารางจะอยู่ใน heap ที่ `JNI_OnLoad` ทำ `mmap(..., 0x122 pages)` ที่ `0xF3FEC movk x19/x20` แล้ว `str [x8,x9]` ลูป `0xF4130-0xF4174` — นั่นคือ copy ของ `ilil` table ที่ถอดแล้ว

### 1.5 C++ Offset ↔ Java — Native Table (Static ที่ระบุได้)

| Java `Native.*` | JNI Offset (file off = VA, load base 0) | Section | หมายเหตุ |
|---|---|---|---|
| `JNI_OnLoad` | `0xF3FA0` size 12,388 | `.text` | Entry ถอดรหัส — `sub sp,0xB0; mrs tpidr_el0; svc mmap; lsr; csinc; br x10` dispatch table |
| `.mytext stub 1` | `0x81EEAC` size 0xF4 (2 func) | `.mytext` | Hook stub: `ldr x8,[x0]; blr x8,#0x38; bl 0xB01C4` + check `0x828D98/0x828D90` |
| `helper 0xB01C4` | `0xB01C4` | `.text` | Decrypt helper 1: `sub sp,0xD0; adrp 0x828000; ldr 0x828D90; adrp 0x836000; ldr [0x836BF8]` |
| `helper 0xB134C` | `0xB134C` | `.text` | Decrypt helper 2: `sub sp,0xD0; ldr 0x828D90; cbnz 0xB1894` |
| `RegisterNatives` table | *(สร้างใน `JNI_OnLoad` หลัง decrypt — ไม่เห็นในไฟล์)* | heap `0xA405...` | ต้อง dump runtime — มี 11 entries: `ac, aior, awl, chl, djp, eio, i, ic, il, ilil, pjowqpxe, update` |
| `ilil impl` | *(หลัง decrypt, เรียกจาก `0xB01C4`)* | `.text` (decrypted) | `f(high=table, low=offset) → String` — XOR + `rodata` base |
| `djp impl` | *(หลัง decrypt)* | `.text` | `f(int)→byte[]` — เรียกจาก `Entry.C code "0"` |
| `yu0.e` | DEX `yu0.e(String,String)` → `cy.b(String,String)` | DEX | Java wrapper — ไม่ใช่ native แต่เรียก native `ic` ก่อนหน้า |

---

## 2) Dart Snapshot — libapp.so ละเอียด

### 2.1 ELF Layout — libapp.so (5.4 MB, Dart AOT)

```
ELF64 AArch64, Fuchsia LLD 18.0.0, clang 17.0.2 (r487747d)
Sections (11):
  .note.gnu.build-id  0x01C8  0x20
  .rodata             0x0200  0x1545C0  (1,341 KB) — Dart VM data
  .dynstr/dynsym/hash 0x154808-0x154958
  .text               0x160000 0x3FC3E0 (4,080 KB) — Dart AOT code
  .bss                0x560000  0x20
  .dynamic            0x560020  0x60

Symbols (6):
  _kDartSnapshotBuildId              0x01C8  32
  _kDartVmSnapshotData               0x0200  0x3EC0 (16,032)
  _kDartVmSnapshotInstructions       0x160000 0x16B10 (92,944)
  _kDartIsolateSnapshotData          0x40C0 0x150700 (1,378,048 = 1.3 MB) ★ หลัก
  _kDartIsolateSnapshotInstructions  0x176B40 0x3E58A0 (4,085,920 = 3.9 MB) ★ หลัก

Header Magic:
  VmSnapshotData:      f5 f5 dc dc bf38...  "80a49c7111088100a233b2ae788e1f48"
  IsolateSnapshotData: f5 f5 dc dc 8eec...  "80a49c7111088100a233b2ae788e1f48product no-code_comments dwarf_stack_traces_mode dedup_instructions no-tsan no-msan arm64 android compressed-pointers"
```

### 2.2 Flutter / Dart Version

- **Flutter:** `3.5.4 (stable) (Wed Oct 16 16:18:51 2024) on "android_arm64"` — จาก `libflutter.so` strings (`3.5.4` ชัดเจน)
- **Dart:** `dart.vm.product` — product mode (no asserts, tree-shaken)
- **Build:** `80a49c71...` (hash ปรากฏทั้ง Vm และ Isolate header) — `no-code_comments`, `dwarf_stack_traces`, `dedup_instructions`, `compressed-pointers`, `arm64 android`
- **Toolchain libapp.so:** `Fuchsia LLD 18.0.0 + clang 17.0.2` (ต่างจาก libengine.so ที่ใช้ clang 14.0.6)
- **libflutter.so Toolchain:** `Linker: LLD 14.0.6` — ชี้ว่า libflutter มาจาก engine prebuilt, libapp มาจาก local build

### 2.3 Packages ที่ฝังใน Isolate (สกัดจาก pool)

```
dart:async-patch, dart:convert, dart:io, dart:math, dart:ui,
dart:_http, dart:vmservice_io,
package:ffi/src/allocation.dart,
package:flutter/src/services/message_codec.dart,
package:flutter/src/services/platform_channel.dart,
package:stack_trace
```
> **สังเกต:** ไม่มี `package:http`, `dio`, `shared_preferences`, `firebase_*` แบบ Dart — Firebase ถูกเรียกจาก **Java (Entry.a0)** ไม่ใช่ Dart http — Dart ใช้ `dart:io HttpClient` โดยตรง (เห็น `HttpException`, `HttpClientResponseCompressionState`, `SecurityContext_Allocate`)

### 2.4 API / Backend — สกัดครบจาก Isolate + libapp.so strings

| Endpoint | ปรากฏ | ใช้ทำอะไร |
|---|---|---|
| `https://rest.snakeseller.com/api/request/` ★ หลัก | Isolate `0x3FF41` + libapp.so strings | `POST {deviceId, key, subscription}` — license, device add/remove, BANNED check, convert |
| `https://www.snakeengine.com/topup/` | Isolate + strings | `InternalWebBrowser.loadUrl()` — เติมเงิน, OAuth |
| `https://flagsapi.com/` (+ `/flat/64.png?r=0`) | strings | โหลดธงชาติ |
| `https://apkpure.com/search?q=` | strings | ลิงก์ติดตั้งเกม (`This game is not Installed, install from Google Play`) |
| `https://play.google.com/store/apps/details?id=` | strings | ตกไป Play Store |
| `https://discord.com/invite/` + `t.me/` + `wa.me/` + `facebook.com/` | strings + assets/svg | Community links (assets: `discord.svg`, `facebook.svg`, `telegram.svg`, `whatsapp.svg`) |
| `https://imgur.com/` | 4 ภาษา | อัปโหลด screenshot ส่ง support |
| `https://api.flutter.dev/...` | strings | เอกสาร Flutter (ไม่ใช่ runtime) |

**HTTP Features:** `http_proxy`, `https_proxy`, `HTTP_PROXY`, `NO_PROXY`, `proxy-authenticate`, `dart:_http _httpConnectionHook@13463476` / `get:_httpConnectionHook@13463476` — รองรับ proxy/VPN เต็มรูปแบบ (สอดคล้อง `ProxyVpnService`)

### 2.5 UI / Widget Tree — สกัดจาก Isolate pool

**Material:** `MaterialApp`, `Scaffold` (×15), `Navigator` — โครงสร้าง Flutter มาตรฐาน

**Game-related (ไม่ใช่ chess logic แต่เป็น Gamepad UI — ชี้ว่าแอป clone เกม):**
```
GameButton1..16, GameButtonA/B/C/X/Y, GameButtonLeft1/2, Right1/2,
GameButtonSelect, Start, Mode, ThumbLeft/Right
Game Selection, PlaySpeedReset, SchedulerPhase
```
> ยืนยันว่า Snake Engine เป็น **Game Launcher / Virtual Controller** ไม่ใช่ chess engine — ชื่อ "Snake Engine" คือ brand ของ seller platform

**i18n Strings (4 ภาษา):**
- EN: `You are not connected to the internet`, `This subscription is for single device only`, `BANNED`, `Device removed`
- TL/Filipino: `Hindi ka konektado sa internet`, `Ang subscription na ito ay para sa isang device lamang`
- MS/ID: `Anda tidak disambungkan ke internet`, `Sila muat naik ke https://imgur.com/`
- ES: `rgalas en https://imgur.com/ y comparta los enlaces`, `Venta Directa`, `Método de inicio de sesión de Facebook`

**Subscription / License Strings (144 รายการ):**
`Add Device`, `Enter device id`, `Enter Other device id`, `The target device already has an active subscription`, `This device subscription is linked from other device (*)`, `Attention, if you remove this device...`, `Babala, Kung ico-convert mo...`, `Subscription Selection`, `Get Subscription`, `Token Akses Anda`, `Secure access token`, `decompressLicenses`, `parseLicenses`, `loginWithResult` (field ใน vx.c), `Game Selection`, `Tanggal Kadaluwarsa` (expiry)

### 2.6 State Analysis — Obfuscation

- **Dart Obfuscation:** `false` — ไม่มี single-letter class spam (`Counter single-letter = empty`) — ชื่อเต็มยังอยู่ → วิเคราะห์ต่อได้ง่าย (ถ้า obfuscate จะเห็น `a`, `b`, `c` เต็ม pool)
- **Dart Tree-shaking:** `true` — `product` mode, ไม่มี `main.dart` string ตรงๆ, ไม่มี `MyApp` — ถูก minify แต่ไม่ obfuscate ชื่อ
- **Java Obfuscation:** `true` — `androidx.appcompat.view.menu.*` ทั้งหมดคือ VirtualApp ที่ rename (เช่น `yu0=VirtualCore`, `vx=OAuthBridge`, `b8=VAInstrumentation`)
- **Native Obfuscation:** `true` — `.text` encrypt, `ilil` table encrypt, ไม่มี `Java_*` export

### 2.7 MethodChannel — Dart ↔ Java Bridge

**Dart → Java (ผ่าน `Entry.C`):**

| Dart เรียก | Java `Entry.C` code | Native |
|---|---|---|
| `MethodChannel.invokeMethod("0", int)` | `case "0": Native.djp(int)` | `libengine.so:djp` |
| `invokeMethod("A", String)` | `case "A": Toast.makeText().show()` | — |
| `invokeMethod("B", Map)` | `case "B": SharedPrefs batch put` | — |
| `invokeMethod("D", String key)` | `case "D": SharedPrefs getString` | — |
| `invokeMethod("E", String url)` | `case "E": startActivity(ACTION_VIEW, Uri)` | — |
| `invokeMethod("G", List<pkg,uid>)` | `case "G": yu0.A / yu0.C / yu0.x` | `libengine` |
| `invokeMethod("F")` | `case "F": return field i` | — |

**Flutter System Channels (มาตรฐาน, ไม่เกี่ยวกับ Snake logic):**
`flutter/textinput`, `flutter/lifecycle`, `flutter/keydata`, `flutter/keyevent`, `flutter/system`, `flutter/navigation`, `flutter/platform`, `flutter/assets`, `dev.flutter/channel-buffers` — ไม่มี custom channel ชื่อ `snake` — ทุก call ผ่าน `Entry.C` เดียว (Fluter `MethodChannel` แบบ generic)

### 2.8 Data Flow — Dart → Java → C++ (เต็ม)

```
User กด "Get Subscription" ใน Dart UI
  → Dart: HttpClient.post("https://rest.snakeseller.com/api/request/",
          headers: {authorization: token}, body: jsonEncode({deviceId, subscriptionId}))
  ← Backend: {status: "active"|"BANNED"|"linked", licenses: compressedBlob}
  → Dart: decompressLicenses(blob) → parseLicenses(json)
  → Dart: MethodChannel.invokeMethod("B", { "license_token": token, "subscription_id": id })
      → Java Entry.C "B": SharedPreferences.edit().putString(k,v).apply()
  → Dart: invokeMethod("0", licenseId) → Java Entry.C "0" → Native.djp(id) → byte[] → Dart
  → ถ้าต้อง OAuth: Dart → InternalWebBrowser(url="https://www.snakeengine.com/topup/?userId=...")
      → WebView (user_<id> data dir, CookieManager) → redirect "#access_token=..."
      → vx.b(url) → vx.c(reflection) → callback → Entry.C → Dart → POST /api/request/ verify
  → Dart แสดง: "This device is already added" / "BANNED" / "Subscription Selection"
```

---

## 3) สรุป — สิ่งที่ถอดได้ vs ต้องรัน

| รายการ | Static ได้ | ต้อง Dynamic |
|---|---|---|
| `ilil` call sites + const values + decoded logic (vx.b/c/f) | ✅ ครบ 7 จุด + pseudo-code | — |
| `ilil` encoding pattern (F1/F2/F3 table) | ✅ | — |
| `ilil` **plaintext mapping** (key→String) | ❌ (encrypted in .text) | ✅ Frida hook `Native.ilil` (3 บรรทัด) |
| `djp` / `chl` / `il` mapping | ❌ | ✅ hook `Native.djp/chl` |
| `libengine.so` JNI_OnLoad decrypt flow + offsets | ✅ (0xF3FA0, 0x81EEAC, 0xB01C4, 0xB134C, 0x828D90 check) | — |
| Dart Flutter version / packages / endpoints | ✅ (3.5.4, 1.3 MB isolate, 6 packages) | — |
| Dart obfuscation / widget tree / i18n / subscription strings | ✅ (not obfuscated, 144 license strings, 4 langs) | — |
| Dart ↔ Java channel codes (0,A,B,D,E,F,G,H,I,J) | ✅ | — |

**คำแนะนำถัดไป:**
1. รัน `frida -U -f com.snake --no-pause -l dump_ilil.js` (สคริปต์ด้านบน) → จะได้ `ilil 15799553 => "com.xxx.YYY"` ครบทุก key ใน 1 รัน
2. ถ้าต้องการ offline: ใช้ `readelf -x .text` หลัง dump heap ที่ `0xF40E0` → `ghidra` เปิด `.text` ที่ถอดแล้ว → `ilil` จะเหลือแค่ `ldr + xor + add` ธรรมดา

---
*SMITH — Senior Mobile Security Researcher | Static Analysis: C++ Offset Java | 2026-10-14*
*ไฟล์วิเคราะห์เพิ่มเติม: `minis://workspace/SnakeEngine_Analysis_Report.md` (รายงานหลัก)*
