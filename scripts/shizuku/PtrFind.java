import java.io.*;
import java.util.*;

public class PtrFind {
    public static void main(String[] args) throws Exception {
        String dir = args[0];
        long lo = Long.parseUnsignedLong(args[1], 16);
        long hi = Long.parseUnsignedLong(args[2], 16);
        File d = new File(dir);
        File[] fs = d.listFiles();
        Arrays.sort(fs, new Comparator<File>() { public int compare(File a, File b) { return a.getName().compareTo(b.getName()); } });
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter("/data/local/tmp/shizuku-ilil/ptrfind-result.txt", false)), true);
        for (File f : fs) {
            if (!f.getName().endsWith(".bin")) continue;
            byte[] data = readAll(f);
            if (data.length == 0) continue;
            List<String> hits = new ArrayList<>();
            for (int i = 0; i + 8 <= data.length; i += 8) {
                long v = read64(data, i);
                if (Long.compareUnsigned(v, lo) >= 0 && Long.compareUnsigned(v, hi) < 0) {
                    hits.add(String.format("+0x%x=%x", i, v));
                }
            }
            // also unaligned scan (step 1) for robustness on smaller files
            if (hits.isEmpty() && data.length <= 1048576) {
                for (int i = 0; i + 8 <= data.length; i++) {
                    long v = read64(data, i);
                    if (Long.compareUnsigned(v, lo) >= 0 && Long.compareUnsigned(v, hi) < 0) {
                        hits.add(String.format("+0x%x=%x", i, v));
                    }
                }
            }
            if (!hits.isEmpty()) {
                w.println("FILE " + f.getName() + " size=" + data.length + " hits=" + hits.size());
                int c = 0;
                for (String h : hits) { w.println("   " + h); if (++c >= 40) { w.println("   ..."); break; } }
            }
        }
        w.println("=== PtrFind DONE ===");
        w.close();
    }
    static byte[] readAll(File f) throws IOException {
        long n = f.length();
        if (n > 33554432L) return new byte[0];
        byte[] b = new byte[(int) n];
        DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(f)));
        try { in.readFully(b); } catch (Exception e) { }
        in.close();
        return b;
    }
    static long read64(byte[] d, int o) {
        return (d[o] & 0xFFL) | ((d[o+1] & 0xFFL) << 8) | ((d[o+2] & 0xFFL) << 16) | ((d[o+3] & 0xFFL) << 24)
             | ((d[o+4] & 0xFFL) << 32) | ((d[o+5] & 0xFFL) << 40) | ((d[o+6] & 0xFFL) << 48) | ((d[o+7] & 0xFFL) << 56);
    }
}
