package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {
    // 2048-bit MODP Group from RFC 3526
    private static final String HEX_PRIME =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    // Generator value
    private static final BigInteger g = BigInteger.valueOf(2);

    // Modulus N
    private static final BigInteger N = new BigInteger(HEX_PRIME, 16);

    private BigInteger privateKey;  // Private key
    private BigInteger publicKey;   // Public key

    /**
     * Initialize Diffie-Hellman and generate key pair
     */
    public DiffieHellman() {
        generateKeyPair();
    }

    /**
     * Generate new DH key pair
     */
    public void generateKeyPair() {
        SecureRandom random = new SecureRandom();

        // Generate random private key (positive integer less than N)
        privateKey = new BigInteger(N.bitLength() - 1, random);

        // Calculate public key: g^privateKey mod N
        publicKey = g.modPow(privateKey, N);
    }

    /**
     * Calculate shared secret using other party's public key
     * @param otherPublicKey Other party's DH public key
     * @return Shared secret
     */
    public byte[] computeSharedSecret(BigInteger otherPublicKey) {
        // Calculate shared secret: otherPublicKey^privateKey mod N
        BigInteger sharedSecret = otherPublicKey.modPow(privateKey, N);

        // Convert to byte array
        return sharedSecret.toByteArray();
    }

    // Getters
    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public static BigInteger getGenerator() {
        return g;
    }

    public static BigInteger getModulus() {
        return N;
    }
}