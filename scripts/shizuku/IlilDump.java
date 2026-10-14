import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.io.*;
import java.util.zip.*;

public class IlilDump {
    public static void main(String[] args) throws Exception {
        String apk = args.length > 0 ? args[0] : "/data/app/~~a0wmsQ5noq8Ui7wejPnOCg==/com.snake-3MlU-xL0AJCdJaYulx3x9Q==/base.apk";
        // Extract to app-private dir when running as app uid, fallback to /data/local/tmp when root
        String extractDir = new File("/data/user/0/com.snake/cache").exists() ? "/data/user/0/com.snake/cache/shizuku-ilil" : "/data/local/tmp/shizuku-ilil";
        new File(extractDir).mkdirs();
        System.out.println("[shizuku-ilil] uid=" + 0 + " apk=" + apk + " extractDir=" + extractDir);
        String soPath = extractDir + "/libengine.so";
        try {
            ZipFile zf = new ZipFile(apk);
            extractEntry(zf, "lib/arm64-v8a/libengine.so", soPath);
            System.out.println("[shizuku-ilil] extracted so " + soPath + " size=" + new File(soPath).length());
            zf.close();
        } catch (Throwable t) { System.out.println("[extract] fail: " + t); t.printStackTrace(); }

        // Critical: pass correct lib dir to PathClassLoader so it can find native libs
        // But also System.load explicitly after PathClassLoader? Actually System.load before class load triggers JNI_OnLoad
        try {
            System.load(soPath);
            System.out.println("[shizuku-ilil] System.load OK");
        } catch (Throwable t) {
            System.out.println("[shizuku-ilil] System.load fail: " + t);
            t.printStackTrace();
        }

        ClassLoader parent = ClassLoader.getSystemClassLoader();
        Class<?> pclClass = Class.forName("dalvik.system.PathClassLoader");
        Constructor<?> ctor = pclClass.getConstructor(String.class, String.class, ClassLoader.class);
        Object pcl = ctor.newInstance(apk, extractDir, parent);
        ClassLoader cl = (ClassLoader) pcl;
        System.out.println("[shizuku-ilil] PathClassLoader=" + cl);

        Class<?> Native = null;
        try {
            Native = cl.loadClass("com.snake.helper.Native");
            System.out.println("[shizuku-ilil] Native=" + Native);
        } catch (Throwable t) {
            System.out.println("[shizuku-ilil] load Native failed: " + t);
            t.printStackTrace(); System.exit(2);
        }
        for (Method m : Native.getDeclaredMethods()) System.out.println("  Native." + m);

        int[] probes = {15799041, 15799553, 15865089, 15930625, 15799584, 15799585, 0, 1, 61, 2, 3, 4, 5, 100, 1000, 0xF11500, 0xF11301, 0xF21501};
        Method ilil = null, djp = null;
        try { ilil = Native.getDeclaredMethod("ilil", int.class); ilil.setAccessible(true);} catch (Throwable t){ System.out.println("no ilil(int): "+t);}
        try { djp = Native.getDeclaredMethod("djp", int.class); djp.setAccessible(true);} catch (Throwable t){ System.out.println("no djp(int): "+t);}

        if (ilil != null) {
            for (int k : probes) {
                try {
                    Object r = ilil.invoke(null, k);
                    String s = String.valueOf(r);
                    String esc = s==null?"null":s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n");
                    System.out.println("[ilil] " + k + " 0x" + Integer.toHexString(k) + " => \"" + esc.substring(0,Math.min(120,esc.length())) + "\" (" + (r==null?0:s.length()) + ")");
                } catch (Throwable t){ System.out.println("[ilil] "+k+" ERROR: "+ (t.getCause()!=null?t.getCause():t)); }
            }
            System.out.println("[shizuku-ilil] brute 0xF11300..0xF11530 + F21500..F21530");
            for (int base : new int[]{0xF11300, 0xF11500, 0xF21500, 0xF31500}) {
                for (int delta=0; delta<0x30; delta++) {
                    int k = base + delta;
                    boolean isProbe=false; for(int p:probes) if(p==k) isProbe=true;
                    if(isProbe) continue;
                    try {
                        Object r = ilil.invoke(null, k);
                        String s = String.valueOf(r);
                        if (s!=null && !s.equals("null") && s.length()>=2 && s.length()<80 && !s.contains("\u0000")) {
                            System.out.println("  [brute] 0x" + Integer.toHexString(k) + " => \"" + s + "\"");
                        }
                    } catch (Throwable t){}
                }
            }
        }
        if (djp != null) {
            for (int k : new int[]{0,1,2,3,4,5,10}) {
                try {
                    Object r = djp.invoke(null, k);
                    byte[] b = (byte[])r;
                    String hx = b==null?"<null>":(b.length + "B " + bytesToHex(b, 64));
                    System.out.println("[djp] " + k + " => " + hx);
                    if (b!=null && b.length>0 && b.length<200) {
                        try { String utf=new String(b,"UTF-8"); System.out.println("  utf: "+utf.substring(0,Math.min(120,utf.length())));} catch(Throwable tt){}
                    }
                } catch (Throwable t){ System.out.println("[djp] "+k+" ERROR: "+t.getCause());}
            }
        }
        try {
            Class<?> vx = cl.loadClass("androidx.appcompat.view.menu.vx");
            System.out.println("[shizuku-ilil] vx="+vx);
            for (Method m : vx.getDeclaredMethods()) System.out.println("  vx."+m.getName()+m);
        } catch(Throwable t){ System.out.println("[shizuku-ilil] vx not found: "+t);}
        System.out.println("[shizuku-ilil] DONE");
        // Also save to file
        try {
            File out = new File(extractDir + "/ilil-live-result.log");
            FileWriter fw = new FileWriter(out);
            fw.write("[shizuku-ilil] done at " + System.currentTimeMillis() + "\n");
            if (ilil!=null) for(int k: probes){ try{ Object r=ilil.invoke(null,k); fw.write("[ilil] "+k+" 0x"+Integer.toHexString(k)+" => \""+String.valueOf(r)+"\"\n"); } catch(Throwable t){ fw.write("[ilil] "+k+" ERR "+t.getCause()+"\n"); } }
            fw.close();
            System.out.println("[shizuku-ilil] saved to " + out.getAbsolutePath() + " " + out.length());
        } catch(Throwable t){ System.out.println("save fail: "+t);}
    }
    static void extractEntry(ZipFile zf, String entryName, String outPath) throws Exception {
        ZipEntry e = zf.getEntry(entryName);
        if (e==null){ System.out.println("[extract] entry not found: "+entryName); return; }
        InputStream is = zf.getInputStream(e);
        File out = new File(outPath);
        out.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(out);
        byte[] buf=new byte[8192]; int n;
        while((n=is.read(buf))>0) fos.write(buf,0,n);
        fos.close(); is.close();
    }
    static String bytesToHex(byte[] b, int max){
        StringBuilder sb=new StringBuilder();
        for(int i=0;i<Math.min(b.length,max);i++){ sb.append(String.format("%02x",b[i]&0xFF)); if(i%16==15) sb.append(" ");}
        if(b.length>max) sb.append("...");
        return sb.toString();
    }
}
