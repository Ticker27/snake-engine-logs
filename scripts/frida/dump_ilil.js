// dump_ilil.js — Frida script for com.snake Native ilil/djp/chl runtime dump
// Usage (device / emulator, com.snake installed):
//   frida -U -f com.snake --no-pause -l scripts/frida/dump_ilil.js
// Output: [ilil]/[djp]/[chl] logs + argv probe for the 6 known constants
// Notes: libengine.so plaintext is encrypted until JNI_OnLoad (0xF3FA0) decrypts .text
//        — only runtime can reveal ilil table (F1/F2/F3 encoding).

'use strict';

function hex(bytes) {
  if (!bytes) return '<null>';
  try {
    const arr = Array.from(bytes);
    return arr.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
  } catch (_) { return String(bytes); }
}

Java.perform(function () {
  const Native = Java.use('com.snake.helper.Native');
  const tag = '[snake-ilil]';

  // Probe the 6 known constants on load (no hook) — also covers the F1/F2/F3 table
  const probes = [15799041, 15799553, 15865089, 15930625, 15799584, 15799585, 1, 61];
  console.log(tag, 'probing', probes.length, 'constants...');
  for (const k of probes) {
    try {
      const r = Native.ilil.overload('int').call(Native, k);
      console.log(tag, '[probe ilil]', k, '(0x' + k.toString(16) + ') =>', JSON.stringify(r));
    } catch (e) {
      console.log(tag, '[probe ilil] ERROR', k, e.message);
    }
  }
  try {
    // Entry.C code "0" path: djp
    const r0 = Native.djp.overload('int').call(Native, 0);
    console.log(tag, '[probe djp] 0 =>', r0 ? hex(r0) : '<null>');
  } catch (e) {
    console.log(tag, '[probe djp] skip:', e.message);
  }

  // Install hooks — log every future call (with stack for caller)
  Native.ilil.overload('int').implementation = function (key) {
    const ret = this.ilil(key);
    const stack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
    const caller = (stack.split('\n')[3] || '').trim();
    console.log(tag, '[ilil]', key, '(0x' + key.toString(16) + ') =>', JSON.stringify(ret), '|', caller);
    return ret;
  };

  try {
    Native.djp.overload('int').implementation = function (key) {
      const ret = this.djp(key);
      console.log(tag, '[djp]', key, '=>', ret ? hex(ret).slice(0, 128) : '<null>', ret ? '(' + ret.length + ' bytes)' : '');
      return ret;
    };
  } catch (_) {}

  try {
    Native.chl.overload('[B').implementation = function (bytes) {
      const ret = this.chl(bytes);
      console.log(tag, '[chl]', bytes ? hex(bytes).slice(0, 64) : '<null>', '=>', ret);
      return ret;
    };
  } catch (_) {}

  // Also watch vx bridge to show the full OAuth flow
  try {
    const vx = Java.use('androidx.appcompat.view.menu.vx');
    vx.b.overload('java.lang.String', 'long', 'boolean').implementation = function (s, ts, flag) {
      console.log(tag, '[vx.b] url=', JSON.stringify(s), 'ts=', ts, 'flag=', flag);
      return this.b(s, ts, flag);
    };
    vx.c.overload('long', 'int', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'boolean').implementation = function (ts, code, a, b, c, flag) {
      console.log(tag, '[vx.c] ts=', ts, 'code=', code, 'a=', JSON.stringify(a), 'b=', JSON.stringify(b), 'c=', JSON.stringify(c), 'flag=', flag);
      return this.c(ts, code, a, b, c, flag);
    };
    vx.f.overload('android.app.Activity', 'java.lang.String', 'int', 'long', 'boolean').implementation = function (act, pkg, code, ts, flag) {
      console.log(tag, '[vx.f] pkg=', pkg, 'code=', code, 'ts=', ts);
      return this.f(act, pkg, code, ts, flag);
    };
    console.log(tag, 'vx hooks installed');
  } catch (e) {
    console.log(tag, 'vx hook skip (obfuscated name may differ):', e.message);
  }

  console.log(tag, 'hooks ready — trigger OAuth/top-up or Game launch to see [vx.*] flow');
});
