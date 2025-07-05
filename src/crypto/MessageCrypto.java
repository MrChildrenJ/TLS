package crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MessageCrypto {
    private SecretKey encryptKey;
    private SecretKey macKey;
    private IvParameterSpec iv;

    /**
     * Initialize message encryption tool
     */
    public MessageCrypto(SecretKey encryptKey, SecretKey macKey, IvParameterSpec iv) {
        this.encryptKey = encryptKey;
        this.macKey = macKey;
        this.iv = iv;
    }

    /**
     * Encrypt and authenticate message
     * @param message Original message
     * @return Encrypted message
     */
    public byte[] encryptAndAuthenticate(byte[] message)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // Calculate MAC
        byte[] mac = generateMAC(message);

        // Concatenate message and MAC
        byte[] messageWithMac = new byte[message.length + mac.length];
        System.arraycopy(message, 0, messageWithMac, 0, message.length);
        System.arraycopy(mac, 0, messageWithMac, message.length, mac.length);

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
        return cipher.doFinal(messageWithMac);
    }

    /**
     * Decrypt and verify message
     * @param encryptedMessage Encrypted message
     * @return Original message, or null if verification fails
     */
    public byte[] decryptAndVerify(byte[] encryptedMessage)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // Decrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, encryptKey, iv);
        byte[] decrypted = cipher.doFinal(encryptedMessage);

        // MAC length is 32 bytes (SHA-256 output)
        int macLength = 32;

        // Separate message and MAC
        if (decrypted.length < macLength) {
            throw new IllegalArgumentException("The decrypted message is too short to contain a MAC.");
        }

        byte[] message = Arrays.copyOfRange(decrypted, 0, decrypted.length - macLength);
        byte[] receivedMac = Arrays.copyOfRange(decrypted, decrypted.length - macLength, decrypted.length);

        // Verify MAC
        byte[] calculatedMac = generateMAC(message);
        boolean macValid = Arrays.equals(receivedMac, calculatedMac);

        if (!macValid) {
            System.err.println("MAC verification failed:");
            System.err.println("MAC received: " + Arrays.toString(receivedMac));
            System.err.println("MAC computed: " + Arrays.toString(calculatedMac));
            return null;
        }

        return message;
    }

    /**
     * Generate HMAC for handshake message
     */
    public byte[] generateHandshakeMAC(byte[] handshakeData)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] result = generateMAC(handshakeData);
//        System.out.println("Generated HMAC for handshake data: " + Arrays.toString(result));
//        // Output key information for debugging
//        System.out.println("HMAC Key Algorithm: " + macKey.getAlgorithm());
//        System.out.println("HMAC Key Format: " + macKey.getFormat());
//        System.out.println("HMAC Key Hash: " + Arrays.toString(macKey.getEncoded()));
        return result;
    }

    /**
     * Generate HMAC
     */
    private byte[] generateMAC(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        return mac.doFinal(data);
    }
}