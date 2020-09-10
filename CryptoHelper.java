import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class CryptoHelper {
    // CONSTANTS
    private static final String ENCODING = "US-ASCII";

    // Encryption
    private static final int LEN_KEY = 8;
    private static final int LEN_SIGN = 8;
    private static final int LEN_ENCRYPTED = 128;

    private static final long PK_SERVER = 83639845798344785L;
    private static final long SIGNATURE = 398098863475112337L;

    // PROPERTIES
    byte[] certTrue;
    byte[] signature;

    // CONSTRUCTOR
    public CryptoHelper() throws UnsupportedEncodingException {
        // Expected Certificate
        byte[] part1 = "NAME=www.pa2.comPK=".getBytes(ENCODING);

        ByteBuffer bb_key = ByteBuffer.allocate(LEN_KEY);
        bb_key.putLong(PK_SERVER);
        byte[] part2 = bb_key.array();


        byte[] part3 = "CA=Bilkent CSSIGNATURE=".getBytes(ENCODING);

        ByteBuffer bb_sign = ByteBuffer.allocate(LEN_SIGN);
        bb_sign.putLong(SIGNATURE);
        signature = bb_sign.array();

        certTrue = new byte[part1.length + part2.length + part3.length + signature.length];
        System.arraycopy(part1, 0, certTrue, 0, part1.length);
        System.arraycopy(part2, 0, certTrue, part1.length, part2.length);
        System.arraycopy(part3, 0, certTrue, part1.length + part2.length, part3.length);
        System.arraycopy(signature, 0, certTrue, part1.length + part2.length + part3.length, signature.length);
    }

    // METHODS
    public boolean verifySignature(byte[] cert, byte[] signature, String ca) {
        if (Arrays.equals(cert, this.certTrue) && Arrays.equals(signature, this.signature) && ca.equals("Bilkent CS")) {
            return true;
        }

        return false;
    }

    public int generateSecret() {
        int secret = new Random().nextInt( (int) (Math.pow(2, 31) - 3) ) + 3;
        if (secret % 2 == 0)
            secret -= 1;
        System.out.println("Generated secret: " + secret);
        return secret;
    }

    public byte[] encryptSecretAsymmetric(int secret, byte[] pk) {
        // Dummy encryption
        long pkNum = ByteBuffer.wrap(pk).getLong();
        long ct = secret + pkNum;

        ByteBuffer bb = ByteBuffer.allocate(LEN_ENCRYPTED);
        bb.putLong(LEN_ENCRYPTED - 8, ct);
        return bb.array();
    }

    public byte[] encryptSymmetric(String data, int secret) throws UnsupportedEncodingException {
        // Convert data to byte, than big integer
        byte[] dataBytes = data.getBytes(ENCODING);
        BigInteger dataNum = new BigInteger(1, dataBytes);

        // Convert secret to big integer
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(secret);
        byte[] secretBytes = bb.array();
        BigInteger secretBigInt = new BigInteger(1, secretBytes);

        // Dummy encryption
        BigInteger ct = dataNum.multiply(secretBigInt);
        byte[] ctBytes = ct.toByteArray();

        // Padding
        byte[] padBytes = new byte[LEN_ENCRYPTED - ctBytes.length];
        Arrays.fill(padBytes, (byte) 0);

        byte[] result = new byte[LEN_ENCRYPTED];
        System.arraycopy(padBytes, 0, result, 0, padBytes.length);
        System.arraycopy(ctBytes, 0, result, padBytes.length, ctBytes.length);
        return result;
    }

    public String decryptSymmetric(byte[] data, int secret) throws UnsupportedEncodingException {
        // Convert data to big integer
        BigInteger ct = new BigInteger(1, data);

        // Convert secret to big integer
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(secret);
        byte[] secretBytes = bb.array();
        BigInteger secretBigInt = new BigInteger(1, secretBytes);

        // Dummy decryption
        BigInteger ptNum = ct.divide(secretBigInt);
        byte[] pt = ptNum.toByteArray();
        String result = new String(pt, ENCODING);
        return result;
    }
}
