# Snake Engine — วิเคราะห์ชุดไฟล์ "เวอร์ชั่นเก่าที่เข้ากันได้" (`com.snake.zip`, 233 ไฟล์ / 7.88 MB)

ชุดนี้คือ **snapshot data dir ของโฮสต์** (`/data/user/0/com.snake/`) ที่เคย **ติดตั้ง/รัน `com.miniclip.eightballpool` สำเร็จ**
ทั้งหมดอยู่ใน `logs/runtime/live/oldsnake-state/` (เฉพาะ conf + inventory + parse; payload เก็บแค่ metadata)

## 1) โครงสร้างที่พบ

```
com.snake/
├── _                                  8 B  = 5b15b5fdc33e0233   (marker/flags — ยังไม่ระบุ)
├── files/                            92 ไฟล์ = แคช C2 (SHA-256 ชื่อไฟล์, 49 KB–454 KB, รูปทั้งหมด)
├── databases/                        Firebase/GA (datatransport.events, google_app_measurement_local.db)
├── shared_prefs/                     Firebase/GA + com.snake.xml → cip_pub (ว่าง แม้ในชุดที่ใช้งานได้)
├── oat/arm64/Anonymous-DexFile@*.vdex  5 ไฟล์ 108–8,748 B  ← **หลักฐาน in-memory DEX**
└── root/                             ← sandbox state จริงของเกสต์
    ├── system/{uid.conf, user.conf, shared-user.conf}
    ├── proc/0/cmdline                = "com.miniclip.eightballpool"
    ├── data/app/com.miniclip.eightballpool/{package.conf (173,904 B), lib/ (ว่าง)}
    ├── data/user/0/com.miniclip.eightballpool/      ← data จริงของเกม (13 โฟลเดอร์)
    └── data/user_de/0/com.miniclip.eightballpool/shared_prefs
```

## 2) ไฟล์ conf — รูปแบบจริง (hex)

| ไฟล์ | ขนาด | bytes | ตีความ |
|---|---|---|---|
| `system/uid.conf` | 8 | `01 00 00 00  00 00 00 00` | `{count=1, uid=0}` → มี 1 package ที่ผูก uid |
| `system/shared-user.conf` | 4 | `00 00 00 00` | `{count=0}` → ไม่มี shared-uid |
| `system/user.conf` | 28 | `01 00 00 00 | 01 00 00 00 | 00 00 00 00 | 00 00 00 00 | ff ff ff ff | 00 00 00 00 | 00 00 00 00` | 7×int32 = `{1, 1, 0, 0, -1, 0, 0}` — นับ 1 user + ธง/ค่า serial (ค่า `-1` = unset) |
| `data/app/<pkg>/package.conf` | 173,904 | (binary record) | ด้านล่าง |

### `package.conf` = record stream `[int32 len][UTF-16 name]` + int32 markers

```
1f 00 00 00   "androidx.appcompat.view.menu.u6"                  ← host STUB class (obfuscated, 31 ตัว)
5f 00 00 00 30 00 00 00   "com.miniclip.eightballpool.EightBallPoolActivity"  ← guest component
00 00 00 00 ff ff ff ff   ← uid/-1 marker
1f 00 00 00   "android.content.pm.ActivityInfo"                   ← ชนิดของ Info ที่ serialize
00 00 00 00 30 00 00 00   ...
```
* **ยืนยันใน `classes.dex`**: `androidx/appcompat/view/menu/u6` **มีจริง** และ `androidx/core/app/CoreComponentFactory` **มีจริง**
  ⇒ `package.conf` เก็บ **mapping host-stub ↔ guest-component** ของทุกคอมโพเนนต์ + metadata
  (ทำไมผู้ใช้เห็น `androidx.core.app.CoreComponentFactory` ตามด้วยคลาสของ framework ในไฟล์นี้)
* 508 UTF-16 strings ครอบคลุม: activities (`Unity ads AdUnit*`, `com.facebook.LoginActivity`, `ProfileInstallReceiver`),
  services/providers/receivers (Firebase, Datatransport, Pangle, `ComponentDiscoveryService`),
  permissions (`INTERNET`, `POST_NOTIFICATIONS`, `AD_ID`, `ACCESS_ADSERVICES_*`, `WAKE_LOCK`, …),
  และเวอร์ชัน: **`56.23.2`**, `com.google.android.play.billingclient.version`, `com.android.vending.splits[.required]`

## 3) Payload ของ engine (เก็บแค่ metadata — ไบต์ไม่ถูกคัดลอกเข้า repo)

ที่ `<guest data>/a0rjgdfbjd8fhfglkew6/90d8aa15a2de2cb4/arm64-v8a/`:

| ไฟล์ | ขนาด | หมายเหตุ |
|---|---|---|
| `libgame-BPM-GooglePlay-Gold-Release-Module-3965.so` | 67,904 B | first16 `887584da…`, **ไม่มี ELF magic** = เข้ารหัส/บีบอัด |
| `libbuffer_pgl.so` | 86 B | `f670605c…` (เข้ารหัส) |
| `libpglarmor.so` | 220 B | `1b676294…` (เข้ารหัส) |

⇒ ชื่อไฟล์บอกชัด: โมดูลสำหรับ 8 Ball Pool บิลด์ **"Gold-Release-Module-3965"** + คู่ `pgl*` (armor bypass)
⇒ และถูกเก็บ **เข้ารหัส** ใต้ path ที่สุ่มชื่อ (สอดคล้องกับ packer `libengine.so` + 496 encrypted blobs)

## 4) การวิเคราะห์ความเข้ากันได้ (ประเด็นหลักที่ถาม)

| ประเด็น | ผล |
|---|---|
| `package.conf` ผูกกับเกมบิลด์ใด | **8 Ball Pool `56.23.2`** (พบ versionName ในไฟล์) |
| เครื่องปัจจุบันติดตั้งอะไร | **`56.31.1` / versionCode `4039`** (base.apk 149 MB) |
| ทะเบียนที่แอปถืออยู่ตอนรัน | `56.31.1@5bee86eda78132ef1f5610e153ca3f20ba71fb8ea2c3de147a5ee65bc0d22405` |
| sha256 ของ APK ในเครื่อง | `d6c94873c7f8c8ff948dc72854bedad6b85e5e66e0acd04e0a85ec6dcd2df45b` (ไม่ตรงกับที่แอปถือ) |
| ⇒ ใช้ชุดไฟล์นี้กับเครื่องนี้ได้ไหม | **ไม่ได้ตรง ๆ** — component list / native lib / versionName ผูกกับบิลด์ (56.23.2) และแอปตรวจ version+hash ก่อนติดตั้ง/รัน |
| ส่วนที่ไม่ผูกกับบิลด์ | `root/system/{uid,user,shared-user}.conf` (โครง sandbox), layout `data/user/%d/%s`, `data/user_de/%d/%s`, `proc/0/cmdline` |

**จะทำให้เข้ากันได้จริง:** ต้องใช้ **8 Ball Pool 56.23.2** (หรือบิลด์ที่แอปรองรับ) + ให้ sandbox สร้าง `package.conf` ใหม่เอง
(ไม่ควรคัดลอก `package.conf` ข้ามบิลด์ เพราะแอปเก็บ `versionName@sha256` ไว้ทดสอบ) — และต้องมีสิทธิ์การใช้งานที่ถูกต้องของเกมนั้น

## 5) สิ่งที่ชุดไฟล์นี้ "ยืนยัน" กับผลวิเคราะห์ก่อนหน้า

1. `package.conf` = component-mapping จริง (ไม่ใช่แค่ชื่อไฟล์) ✅
2. path `data/user/%d/%s` + `data/user_de/%d/%s` ถูกใช้จริง ✅
3. มีการโหลด DEX แบบ **in-memory** (`Anonymous-DexFile@*.vdex` 5 ไฟล์) ✅ ตรงกับ `DexFind` ที่เจอ DEX 99 ตัว
4. native payload ของ engine ถูกเก็บ **เข้ารหัส** ใต้ data ของเกสต์ (ไม่ใช่ `lib/` ของ APK) ✅
5. แม้ในสถานะที่ใช้งานได้ `cip_pub` **ยังว่าง** ⇒ ช่องคีย์ไม่ใช่สิ่งที่ใช้ผูกสิทธิ์ในเส้นทางนี้

---
*หมายเหตุ: รายงานนี้เป็นการวิเคราะห์ไฟล์เท่านั้น — ไม่ได้ทำการ deploy ชุดไฟล์/บายพาสการตรวจสอบสิทธิ์ และไม่ได้คัดลอกไบต์ payload ของโมดูล (เก็บเฉพาะขนาด/แฮช)*
