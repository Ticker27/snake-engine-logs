import java.io.*;

public class RegionScan {
    public static void main(String[] args) throws Exception {
        String path = args[0];
        String needle = args[1];
        int window = args.length > 2 ? Integer.parseInt(args[2]) : 4096;
        byte[] data = readAll(new File(path));
        System.out.println("[RegionScan] file=" + path + " size=" + data.length + " needle=" + needle);
        byte[] n = needle.getBytes("ISO-8859-1");
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter("/data/local/tmp/shizuku-ilil/regionscan-result.txt", false)), true);
        int idx = indexOf(data, n);
        if (idx < 0) { System.out.println("needle not found"); w.println("not found"); w.close(); return; }
        w.println("needle '" + needle + "' at file offset 0x" + Integer.toHexString(idx));
        System.out.println("needle at 0x" + Integer.toHexString(idx));
        int a = Math.max(0, idx - window / 2), b = Math.min(data.length, idx + window / 2);
        w.println("--- strings in window 0x" + Integer.toHexString(a) + "..0x" + Integer.toHexString(b) + " ---");
        int i = a;
        while (i < b) {
            if (data[i] >= 0x20 && data[i] < 0x7f) {
                int j = i;
                while (j < b && data[j] >= 0x20 && data[j] < 0x7f) j++;
                if (j - i >= 4) w.println("  +0x" + Integer.toHexString(i) + ": " + new String(data, i, j - i, "ISO-8859-1"));
                i = j;
            } else i++;
        }
        // dump hex of window
        w.println("--- hexdump ---");
        for (int k = a; k < b; k += 16) {
            StringBuilder sb = new StringBuilder(String.format("  %06x  ", k));
            StringBuilder asc = new StringBuilder();
            for (int m = 0; m < 16 && k + m < b; m++) {
                sb.append(String.format("%02x ", data[k + m]));
                int c = data[k + m] & 0xFF;
                asc.append(c >= 0x20 && c < 0x7f ? (char) c : '.');
            }
            w.println(sb + " |" + asc + "|");
        }
        // also scan whole file for JNI-ish strings
        w.println("--- JNI-ish strings (file-wide, first 300) ---");
        int count = 0;
        i = 0;
        while (i < data.length && count < 300) {
            if (data[i] >= 0x20 && data[i] < 0x7f) {
                int j = i;
                while (j < data.length && data[j] >= 0x20 && data[j] < 0x7f) j++;
                int len = j - i;
                if (len >= 5 && len <= 200) {
                    String s = new String(data, i, j - i, "ISO-8859-1");
                    if (s.contains("Ljava/") || s.contains("Landroid") || s.contains("ilil") || s.contains("snake")
                        || s.contains("jni") || s.contains("JNI") || s.contains("Native") || s.contains("Settings")
                        || s.matches(".*\\(.*\\).*") && s.length() < 80) {
                        w.println("  +0x" + Integer.toHexString(i) + ": " + s);
                        count++;
                    }
                }
                i = j;
            } else i++;
        }
        w.println("=== RegionScan DONE ===");
        w.close();
        System.out.println("saved regionscan-result.txt");
    }
    static byte[] readAll(File f) throws IOException {
        byte[] b = new byte[(int) f.length()];
        DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(f)));
        try { in.readFully(b); } catch (Exception e) {}
        in.close();
        return b;
    }
    static int indexOf(byte[] d, byte[] p) {
        outer:
        for (int i = 0; i + p.length <= d.length; i++) {
            for (int j = 0; j < p.length; j++) if (d[i + j] != p[j]) continue outer;
            return i;
        }
        return -1;
    }
}
