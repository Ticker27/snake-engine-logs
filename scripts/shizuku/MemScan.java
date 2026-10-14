import java.io.*;
import java.util.*;

public class MemScan {
    static final String OUT = "/data/local/tmp/shizuku-ilil/memscan-result.txt";
    static final String DUMPDIR = "/data/local/tmp/shizuku-ilil/dumps";
    static PrintWriter log;
    static long totalBytes = 0;

    public static void main(String[] args) throws Exception {
        int pid = Integer.parseInt(args[0]);
        long maxSecs = args.length > 1 ? Long.parseLong(args[1]) : 300;
        new File(DUMPDIR).mkdirs();
        log = new PrintWriter(new BufferedWriter(new FileWriter(OUT, false)), true);
        String[] pats = {"pjowqpxe", "snakeseller", "RegisterNatives", "com/snake/helper/Native",
                         "ilil", "getApplicationInfo", "snakeengine", "access_token", "libengine"};
        log.println("=== MemScan pid=" + pid + " maxSecs=" + maxSecs + " ===");
        long t0 = System.currentTimeMillis();

        List<String[]> regions = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader("/proc/" + pid + "/maps"));
        String line;
        while ((line = br.readLine()) != null) {
            String[] f = line.split("\\s+");
            if (f.length < 2) continue;
            String range = f[0], perm = f[1];
            String path = f.length >= 6 ? f[5] : "";
            if (!perm.startsWith("r")) continue;
            if (path.startsWith("/")) continue;                 // skip file-backed
            if (path.startsWith("[vvar") || path.startsWith("[vsys") || path.startsWith("[vec")) continue;
            if (path.contains("dmabuf") || path.contains("kgsl") || path.contains("mali")) continue;
            String[] r = range.split("-");
            long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
            long sz = e - s;
            if (sz <= 0 || sz > 134217728L) continue;
            regions.add(new String[]{"" + s, "" + sz, perm, path});
        }
        br.close();
        log.println("anon readable regions: " + regions.size());

        for (String[] reg : regions) {
            if ((System.currentTimeMillis() - t0) / 1000 > maxSecs) { log.println("TIME BUDGET reached"); break; }
            long s = Long.parseLong(reg[0]), sz = Long.parseLong(reg[1]);
            String perm = reg[2], path = reg[3];
            byte[] data = null;
            try {
                RandomAccessFile raf = new RandomAccessFile("/proc/" + pid + "/mem", "r");
                try {
                    raf.seek(s);
                    data = new byte[(int) Math.min(sz, 134217728L)];
                    int off = 0;
                    while (off < data.length) {
                        int n = raf.read(data, off, Math.min(1048576, data.length - off));
                        if (n <= 0) break;
                        off += n;
                    }
                    if (off < data.length) { byte[] d2 = new byte[off]; System.arraycopy(data, 0, d2, 0, off); data = d2; }
                } finally { raf.close(); }
            } catch (Throwable t) {
                continue;
            }
            if (data.length == 0) continue;
            totalBytes += data.length;
            boolean any = false;
            StringBuilder sb = new StringBuilder();
            for (String p : pats) {
                int c = countOccur(data, p.getBytes("ISO-8859-1"));
                if (c > 0) { any = true; sb.append(p).append("=").append(c).append(" "); }
            }
            if (any) {
                String hex = Long.toHexString(s);
                String f = DUMPDIR + "/pid" + pid + "_" + hex + "_" + data.length + ".bin";
                try {
                    FileOutputStream fos = new FileOutputStream(f);
                    fos.write(data.length > 8388608 ? Arrays.copyOf(data, 8388608) : data);
                    fos.close();
                } catch (Throwable t) {}
                log.println("HIT " + hex + " size=" + data.length + " perm=" + perm + " path=" + path + " :: " + sb);
                // context snippet for pjowqpxe (highly unique)
                int idx = indexOf(data, "pjowqpxe".getBytes("ISO-8859-1"));
                if (idx >= 0) {
                    int a = Math.max(0, idx - 160), b = Math.min(data.length, idx + 320);
                    String ctx = new String(data, a, b - a, "ISO-8859-1").replaceAll("[^\\x20-\\x7e]", ".");
                    log.println("  ctx: " + ctx);
                }
                int idx2 = indexOf(data, "snakeseller".getBytes("ISO-8859-1"));
                if (idx2 >= 0) {
                    int a = Math.max(0, idx2 - 120), b = Math.min(data.length, idx2 + 200);
                    log.println("  url: " + new String(data, a, b - a, "ISO-8859-1").replaceAll("[^\\x20-\\x7e]", "."));
                }
            }
        }
        log.println("TOTAL scanned bytes: " + totalBytes + " in " + (System.currentTimeMillis() - t0) / 1000 + "s");
        log.println("=== MemScan DONE ===");
        log.close();
    }

    static int indexOf(byte[] d, byte[] p) {
        outer:
        for (int i = 0; i + p.length <= d.length; i++) {
            for (int j = 0; j < p.length; j++) if (d[i + j] != p[j]) continue outer;
            return i;
        }
        return -1;
    }

    static int countOccur(byte[] d, byte[] p) {
        int c = 0, i = 0;
        while ((i = indexOfFrom(d, p, i)) >= 0) { c++; i += 1; }
        return c;
    }

    static int indexOfFrom(byte[] d, byte[] p, int from) {
        outer:
        for (int i = from; i + p.length <= d.length; i++) {
            for (int j = 0; j < p.length; j++) if (d[i + j] != p[j]) continue outer;
            return i;
        }
        return -1;
    }
}
