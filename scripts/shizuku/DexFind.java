import java.io.*;
import java.util.*;

public class DexFind {
    public static void main(String[] args) throws Exception {
        int pid = Integer.parseInt(args[0]);
        String outDir = args.length > 1 ? args[1] : "/data/local/tmp/shizuku-ilil/dumps";
        new File(outDir).mkdirs();
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter("/data/local/tmp/shizuku-ilil/dexfind-result.txt", false)), true);
        w.println("=== DexFind pid=" + pid + " ===");
        byte[] magic = "dex\n0".getBytes("ISO-8859-1");
        BufferedReader br = new BufferedReader(new FileReader("/proc/" + pid + "/maps"));
        String line;
        int found = 0, regions = 0;
        long scanned = 0;
        while ((line = br.readLine()) != null) {
            String[] f = line.split("\\s+");
            if (f.length < 2) continue;
            String range = f[0], perm = f[1];
            String path = f.length >= 6 ? f[5] : "";
            if (!perm.startsWith("r")) continue;
            if (path.startsWith("[vvar") || path.startsWith("[vsys")) continue;
            String[] r = range.split("-");
            long s = Long.parseUnsignedLong(r[0], 16), e = Long.parseUnsignedLong(r[1], 16);
            long sz = e - s;
            if (sz <= 0 || sz > 201326592L) continue;
            byte[] data;
            try {
                RandomAccessFile raf = new RandomAccessFile("/proc/" + pid + "/mem", "r");
                raf.seek(s);
                data = new byte[(int) Math.min(sz, 201326592L)];
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
            int i = 0;
            while (true) {
                int j = indexOfFrom(data, magic, i);
                if (j < 0) break;
                i = j + 1;
                if (j + 112 > data.length) break;
                // header checks: version at j+4..j+6, file_size at j+32 (u32 LE)
                long fsz = (data[j+32]&0xFFL) | ((data[j+33]&0xFFL)<<8) | ((data[j+34]&0xFFL)<<16) | ((data[j+35]&0xFFL)<<24);
                long hsz = (data[j+36]&0xFFL) | ((data[j+37]&0xFFL)<<8) | ((data[j+38]&0xFFL)<<16) | ((data[j+39]&0xFFL)<<24);
                if (fsz < 0x70 || fsz > 201326592L || hsz != 0x70) continue;
                long abs = s + j;
                String ver = new String(data, j+4, 3, "ISO-8859-1");
                w.println("DEX magic=dex\\n" + ver + " at 0x" + Long.toHexString(abs) + " file_size=" + fsz + " region=[0x" + Long.toHexString(s) + "..)");
                if (j + fsz <= data.length) {
                    String out = outDir + "/inmem_" + Long.toHexString(abs) + ".dex";
                    FileOutputStream fos = new FileOutputStream(out);
                    fos.write(data, j, (int) fsz);
                    fos.close();
                    w.println("    dumped -> " + out);
                    found++;
                } else {
                    w.println("    (truncated in this region, size beyond region end)");
                }
            }
        }
        w.println("regions=" + regions + " scanned=" + scanned + " dumps=" + found);
        w.println("=== DexFind DONE ===");
        w.close();
        System.out.println("done regions=" + regions + " scanned=" + scanned + " dumps=" + found);
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
