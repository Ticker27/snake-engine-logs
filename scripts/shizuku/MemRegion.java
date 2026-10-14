import java.io.*;

public class MemRegion {
    public static void main(String[] args) throws Exception {
        String pid = args[0];
        long start = Long.parseUnsignedLong(args[1], 16);
        long size = Long.parseLong(args[2]);
        String needle = args[3];
        String outFile = args.length > 4 ? args[4] : "/data/local/tmp/shizuku-ilil/dumps/memregion.bin";
        String resFile = "/data/local/tmp/shizuku-ilil/regionscan-result.txt";
        RandomAccessFile mem = new RandomAccessFile("/proc/" + pid + "/mem", "r");
        byte[] data = new byte[(int) Math.min(size, 33554432L)];
        mem.seek(start);
        int off = 0;
        while (off < data.length) {
            int n = mem.read(data, off, Math.min(1048576, data.length - off));
            if (n <= 0) break;
            off += n;
        }
        mem.close();
        if (off < data.length) { byte[] d2 = new byte[off]; System.arraycopy(data, 0, d2, 0, off); data = d2; }
        int nz = 0;
        for (byte b : data) if (b != 0) nz++;
        System.out.println("[MemRegion] pid=" + pid + " start=0x" + Long.toHexString(start) + " read=" + data.length + " nonzero=" + nz);
        try {
            FileOutputStream fos = new FileOutputStream(outFile);
            fos.write(data);
            fos.close();
            System.out.println("[MemRegion] written " + outFile);
        } catch (Throwable t) { System.out.println("write fail: " + t); }

        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(resFile, false)), true);
        w.println("=== MemRegion pid=" + pid + " start=0x" + Long.toHexString(start) + " size=" + data.length + " nonzero=" + nz + " ===");
        byte[] n = needle.getBytes("ISO-8859-1");
        int idx = indexOf(data, n);
        int hits = 0;
        int scanPos = 0;
        while (scanPos < data.length) {
            int f = indexOfFrom(data, n, scanPos);
            if (f < 0) break;
            hits++;
            if (hits <= 12) w.println("needle at +0x" + Integer.toHexString(f) + " (abs 0x" + Long.toHexString(start + f) + ")");
            scanPos = f + 1;
        }
        w.println("needle '" + needle + "' total hits=" + hits);
        if (idx >= 0) {
            int a = Math.max(0, idx - 2048), b = Math.min(data.length, idx + 2048);
            w.println("--- strings around +(0x" + Integer.toHexString(idx) + ") ---");
            int i = a;
            while (i < b) {
                if (data[i] >= 0x20 && data[i] < 0x7f) {
                    int j = i;
                    while (j < b && data[j] >= 0x20 && data[j] < 0x7f) j++;
                    if (j - i >= 4) w.println("  +0x" + Integer.toHexString(i) + ": " + new String(data, i, j - i, "ISO-8859-1"));
                    i = j;
                } else i++;
            }
        }
        // gather JNI-ish strings across whole region
        w.println("--- region strings (JNI-ish, max 400) ---");
        int c = 0, i2 = 0;
        while (i2 < data.length && c < 400) {
            if (data[i2] >= 0x20 && data[i2] < 0x7f) {
                int j = i2;
                while (j < data.length && data[j] >= 0x20 && data[j] < 0x7f) j++;
                int len = j - i2;
                if (len >= 4 && len <= 160) {
                    String s = new String(data, i2, len, "ISO-8859-1");
                    if (s.contains("Ljava/") || s.contains("Landroid") || s.contains("ilil") || s.contains("snake")
                        || s.contains("Native") || s.contains("Settings") || s.contains("()") || s.contains("android_")
                        || s.contains("ro.product") || s.contains("com/")) {
                        w.println("  +0x" + Integer.toHexString(i2) + ": " + s);
                        c++;
                    }
                }
                i2 = j;
            } else i2++;
        }
        w.println("=== MemRegion DONE ===");
        w.close();
        System.out.println("results -> " + resFile);
    }
    static int indexOf(byte[] d, byte[] p) { return indexOfFrom(d, p, 0); }
    static int indexOfFrom(byte[] d, byte[] p, int from) {
        outer:
        for (int i = from; i + p.length <= d.length; i++) {
            for (int j = 0; j < p.length; j++) if (d[i + j] != p[j]) continue outer;
            return i;
        }
        return -1;
    }
}
