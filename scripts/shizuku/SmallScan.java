import java.io.*;
import java.util.*;

public class SmallScan {
    public static void main(String[] args) throws Exception {
        int pid = Integer.parseInt(args[0]);
        int maxSize = args.length > 1 ? Integer.parseInt(args[1], 16) : 0x2000;
        int head = args.length > 2 ? Integer.parseInt(args[2], 16) : 0x100;
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter("/data/local/tmp/shizuku-ilil/smallscan-result.txt", false)), true);
        w.println("=== SmallScan pid=" + pid + " maxSize=0x" + Integer.toHexString(maxSize) + " head=0x" + Integer.toHexString(head) + " ===");
        BufferedReader br = new BufferedReader(new FileReader("/proc/" + pid + "/maps"));
        String line;
        int found = 0;
        while ((line = br.readLine()) != null) {
            String[] f = line.split("\\s+");
            if (f.length < 2) continue;
            String range = f[0], perm = f[1];
            String path = f.length >= 6 ? f[5] : "";
            if (!perm.startsWith("r")) continue;
            if (!(path.isEmpty() || path.startsWith("[anon:"))) continue;
            String[] r = range.split("-");
            long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
            long sz = e - s;
            if (sz <= 0 || sz > maxSize) continue;
            try {
                RandomAccessFile raf = new RandomAccessFile("/proc/" + pid + "/mem", "r");
                raf.seek(s);
                byte[] buf = new byte[head];
                int n = raf.read(buf, 0, head);
                raf.close();
                if (n <= 0) continue;
                int print = 0;
                for (int i = 0; i < n; i++) { int c = buf[i] & 0xFF; if (c >= 0x20 && c < 0x7f) print++; }
                if (print >= 4) {
                    StringBuilder asc = new StringBuilder();
                    for (int i = 0; i < n; i++) { int c = buf[i] & 0xFF; asc.append(c >= 0x20 && c < 0x7f ? (char) c : '.'); }
                    StringBuilder hx = new StringBuilder();
                    for (int i = 0; i < Math.min(n, 96); i++) hx.append(String.format("%02x", buf[i] & 0xFF));
                    w.println(String.format("REG 0x%x size=0x%x perm=%s path=%s", s, sz, perm, path));
                    w.println("   hex: " + hx);
                    w.println("   asc: " + asc.substring(0, Math.min(n, 160)));
                    found++;
                }
            } catch (Throwable t) { }
        }
        br.close();
        w.println("=== SmallScan DONE regions_with_ascii=" + found + " ===");
        w.close();
        System.out.println("done found=" + found);
    }
}
