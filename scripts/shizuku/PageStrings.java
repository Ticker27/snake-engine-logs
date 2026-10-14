import java.io.*;

public class PageStrings {
    public static void main(String[] args) throws Exception {
        String path = args[0];
        int minLen = args.length > 1 ? Integer.parseInt(args[1]) : 2;
        File f = new File(path);
        byte[] data = new byte[(int) f.length()];
        DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(f)));
        try { in.readFully(data); } catch (Exception e) {}
        in.close();
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter("/data/local/tmp/shizuku-ilil/pagestrings-result.txt", false)), true);
        w.println("=== PageStrings " + path + " size=" + data.length + " minLen=" + minLen + " ===");
        int pages = (data.length + 4095) / 4096;
        for (int p = 0; p < pages; p++) {
            int a = p * 4096, b = Math.min(data.length, a + 4096);
            int nz = 0;
            for (int i = a; i < b; i++) if (data[i] != 0) nz++;
            if (nz == 0) continue;
            StringBuilder sb = new StringBuilder();
            int i = a;
            int cnt = 0;
            while (i < b) {
                if (data[i] >= 0x20 && data[i] < 0x7f) {
                    int j = i;
                    while (j < b && data[j] >= 0x20 && data[j] < 0x7f) j++;
                    if (j - i >= minLen) { sb.append("\n     +0x").append(Integer.toHexString(i)).append(" \"").append(new String(data, i, j - i, "ISO-8859-1")).append("\""); cnt++; }
                    i = j;
                } else i++;
            }
            if (cnt > 0) w.println("[page 0x" + Integer.toHexString(a) + "] nonzero=" + nz + sb);
        }
        w.println("=== PageStrings DONE ===");
        w.close();
        System.out.println("done -> pagestrings-result.txt pages=" + pages);
    }
}
