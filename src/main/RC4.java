import java.util.Arrays;

public class RC4 {
    public static byte[] encrypt(byte[] pwd, byte[] data) {
        int[] array = new int[256];
        int[] array2 = new int[256];
        byte[] array3 = new byte[data.length];

        for (int i = 0; i < 256; i++) {
            array[i] = pwd[i % pwd.length] & 0xff;
            array2[i] = i;
        }

        int num = 0;
        for (int i = 0; i < 256; i++) {
            num = (num + array2[i] + array[i]) % 256;
            int num2 = array2[i];
            array2[i] = array2[num];
            array2[num] = num2;
        }

        int num3 = 0;
        num = 0;
        for (int i = 0; i < data.length; i++) {
            num3++;
            num3 %= 256;
            num += array2[num3];
            num %= 256;
            int num2 = array2[num3];
            array2[num3] = array2[num];
            array2[num] = num2;
            int num4 = array2[(array2[num3] + array2[num]) % 256];
            array3[i] = (byte) (data[i] ^ num4);
        }
        return array3;
    }

    public static byte[] decrypt(byte[] pwd, byte[] data) {
        return encrypt(pwd, data);
    }
}