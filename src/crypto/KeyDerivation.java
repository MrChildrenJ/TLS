package crypto;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyDerivation {
    // Session keys
    private SecretKey serverEncryptKey;
    private SecretKey clientEncryptKey;
    private SecretKey serverMacKey;
    private SecretKey clientMacKey;
    private IvParameterSpec serverIv;
    private IvParameterSpec clientIv;

    /**
     * Derive session keys from Diffie-Hellman shared secret
     * @param clientNonce Client nonce
     * @param dhSharedSecret Diffie-Hellman shared secret
     */
    public KeyDerivation(byte[] clientNonce, byte[] dhSharedSecret)
            throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            // Combine nonce and shared secret as base key material
            byte[] combinedSecret = new byte[clientNonce.length + dhSharedSecret.length];
            System.arraycopy(clientNonce, 0, combinedSecret, 0, clientNonce.length);
            System.arraycopy(dhSharedSecret, 0, combinedSecret, clientNonce.length, dhSharedSecret.length);

            // Use different contexts to generate keys for different directions and purposes
            // Server encryption key
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(combinedSecret);
            digest.update("server_encrypt".getBytes());
            byte[] serverEncryptBytes = digest.digest();
            serverEncryptKey = new SecretKeySpec(Arrays.copyOfRange(serverEncryptBytes, 0, 16), "AES");

            // Client encryption key
            digest.reset();
            digest.update(combinedSecret);
            digest.update("client_encrypt".getBytes());
            byte[] clientEncryptBytes = digest.digest();
            clientEncryptKey = new SecretKeySpec(Arrays.copyOfRange(clientEncryptBytes, 0, 16), "AES");

            // Server MAC key
            digest.reset();
            digest.update(combinedSecret);
            digest.update("server_mac".getBytes());
            byte[] serverMacBytes = digest.digest();
            serverMacKey = new SecretKeySpec(serverMacBytes, "HmacSHA256");

            // Client MAC key
            digest.reset();
            digest.update(combinedSecret);
            digest.update("client_mac".getBytes());
            byte[] clientMacBytes = digest.digest();
            clientMacKey = new SecretKeySpec(clientMacBytes, "HmacSHA256");

            // Server IV
            digest.reset();
            digest.update(combinedSecret);
            digest.update("server_iv".getBytes());
            byte[] serverIvBytes = digest.digest();
            serverIv = new IvParameterSpec(Arrays.copyOfRange(serverIvBytes, 0, 16));

            // Client IV
            digest.reset();
            digest.update(combinedSecret);
            digest.update("client_iv".getBytes());
            byte[] clientIvBytes = digest.digest();
            clientIv = new IvParameterSpec(Arrays.copyOfRange(clientIvBytes, 0, 16));

            // Output debug information
            System.out.println("Key derivation completed. Use separate key derivation logic to generate keys for different directions.");
        } catch (Exception e) {
            System.err.println("Key derivation failed: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    // Getters
    public SecretKey getServerEncryptKey() {
        return serverEncryptKey;
    }

    public SecretKey getClientEncryptKey() {
        return clientEncryptKey;
    }

    public SecretKey getServerMacKey() {
        return serverMacKey;
    }

    public SecretKey getClientMacKey() {
        return clientMacKey;
    }

    public IvParameterSpec getServerIv() {
        return serverIv;
    }

    public IvParameterSpec getClientIv() {
        return clientIv;
    }
}