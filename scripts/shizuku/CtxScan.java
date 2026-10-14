import java.io.*;
import java.util.*;

public class CtxScan {
    public static void main(String[] args) throws Exception {
        int pid = Integer.parseInt(args[0]);
        List<String> pats = new ArrayList<>();
        for (int i = 1; i < args.length; i++) pats.add(args[i]);
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter("/data/local/tmp/shizuku-ilil/ctxscan-result.txt", false)), true);
        w.println("=== CtxScan pid=" + pid + " patterns=" + pats);
        BufferedReader br = new BufferedReader(new FileReader("/proc/" + pid + "/maps"));
        String line;
        int regions = 0, hits = 0;
        long scanned = 0;
        while ((line = br.readLine()) != null) {
            String[] f = line.split("\\s+");
            if (f.length < 2) continue;
            String range = f[0], perm = f[1];
            String path = f.length >= 6 ? f[5] : "";
            if (!perm.startsWith("r")) continue;
            if (path.startsWith("[vvar") || path.startsWith("[vsys") || path.startsWith("[vec")) continue;
            String[] r = range.split("-");
            long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
            long sz = e - s;
            if (sz <= 0 || sz > 67108864L) continue;
            byte[] data;
            try {
                RandomAccessFile raf = new RandomAccessFile("/proc/" + pid + "/mem", "r");
                raf.seek(s);
                data = new byte[(int) sz];
                int off = 0;
                while (off < data.length) {
                    int n = raf.read(data, off, Math.min(1048576, data.length - off));
                    if (n <= 0) break;
                    off += n;
                }
                raf.close();
                if (off < data.length) { byte[] d2 = new byte[off]; System.arraycopy(data, 0, d2, 0, off); data = d2; }
            } catch (Throwable t) { continue; }
            if (data.length == 0) continue;
            regions++; scanned += data.length;
            for (String p : pats) {
                byte[] needle = p.getBytes("ISO-8859-1");
                int i = 0;
                while (true) {
                    int j = indexOfFrom(data, needle, i);
                    if (j < 0) break;
                    hits++;
                    long abs = s + j;
                    w.println("HIT '" + p + "' @0x" + Long.toHexString(abs) + " region=[0x" + Long.toHexString(s) + "..) perm=" + perm);
                    int a = Math.max(0, j - 200), b = Math.min(data.length, j + 400);
                    StringBuilder asc = new StringBuilder();
                    for (int k = a; k < b; k++) {
                        int c = data[k] & 0xFF;
                        asc.append((c >= 0x20 && c < 0x7f) ? (char) c : (c == 0 ? '.' : '.'));
                    }
                    w.println("    " + asc);
                    i = j + 1;
                    if (hits > 200) break;
                }
            }
        }
        w.println("regions=" + regions + " scanned=" + scanned + " hits=" + hits);
        w.println("=== CtxScan DONE ===");
        w.close();
        System.out.println("done regions=" + regions + " scanned=" + scanned + " hits=" + hits);
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
