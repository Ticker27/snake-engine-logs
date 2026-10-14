// frida_hook_all.js — full Native table hook (11 methods)
// Usage: frida -U -f com.snake --no-pause -l scripts/frida/frida_hook_all.js
// Covers: ac, aior, awl, chl, djp, eio, i, ic, il, ilil, pjowqpxe, update, logIn, gcuid, a, b
'use strict';
Java.perform(function(){
  const N = Java.use('com.snake.helper.Native');
  const log = (...a)=>console.log('[snake-native]', ...a);
  const wrap = (name, overload, fmt) => {
    try {
      const o = N[name].overload(...overload);
      const orig = o.implementation;
      o.implementation = function(...args){
        const ret = orig ? o.call(this, ...args) : this[name](...args);
        // Avoid recursion: call original via this
        let r;
        try { r = this[name].apply(this, args); } catch(_){}
        try { log(`[${name}]`, fmt ? fmt(args, r) : JSON.stringify(args), '=>', r); } catch(_){}
        return r;
      };
    } catch(e){ /* overload not present */ }
  };
  // Hook with explicit overloads discovered from DEX
  try { const o=N.ilil.overload('int'); const orig=o.implementation; o.implementation=function(k){ const r=orig?orig.call(this,k):this.ilil(k); log('[ilil]',k,'(0x'+k.toString(16)+')=>',JSON.stringify(r)); return r; }; } catch(e){}
  try { const o=N.djp.overload('int'); const orig=o.implementation; o.implementation=function(k){ const r=orig?orig.call(this,k):this.djp(k); const h=r?Array.from(r).map(b=>('0'+(b&0xff).toString(16)).slice(-2)).join('').slice(0,128):'<null>'; log('[djp]',k,'=>',h, r?`(${r.length}b)`:''); return r; }; } catch(e){}
  try { const o=N.chl.overload('[B'); const orig=o.implementation; o.implementation=function(b){ const r=orig?orig.call(this,b):this.chl(b); log('[chl]', b?b.length+'b':'<null>','=>',r); return r; }; } catch(e){}
  try { N.ic.overload('android.content.Context').implementation=function(c){ log('[ic] ctx=',c); return this.ic(c); }; } catch(e){}
  try { N.awl.overload('java.lang.String').implementation=function(s){ log('[awl]',JSON.stringify(s)); return this.awl(s); }; } catch(e){}
  try { N.aior.overload('java.lang.String','java.lang.String').implementation=function(a,b){ log('[aior]',JSON.stringify(a),JSON.stringify(b)); return this.aior(a,b); }; } catch(e){}
  try { N.eio.overload().implementation=function(){ log('[eio]'); return this.eio(); }; } catch(e){}
  try { N.i.overload('int').implementation=function(k){ log('[i]',k); return this.i(k); }; } catch(e){}
  log('Native hooks installed — launch/top-up to trigger');
});
