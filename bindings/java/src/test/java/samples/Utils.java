package samples;

public class Utils {
    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) +
                Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static final int toInt(byte val[]) {
        int res = 0;
        for (int i = 0; i < val.length; i++) {
            int v = val[i] & 0xff;
            res = res + (v << (i * 8));
        }
        return res;
    }

    public static final long toLong(byte val[]) {
        long res = 0;
        for (int i = 0; i < val.length; i++) {
            long v = val[i] & 0xff;
            res = res + (v << (i * 8));
        }
        return res;
    }

    public static final byte[] toBytes(int val) {
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++) {
            res[i] = (byte) (val & 0xff);
            val >>>= 8;
        }
        return res;
    }

    public static final byte[] toBytes(long val) {
        byte[] res = new byte[8];
        for (int i = 0; i < 8; i++) {
            res[i] = (byte) (val & 0xff);
            val >>>= 8;
        }
        return res;
    }
}
