package crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertificateManager {
    private Certificate caCertificate;
    private Certificate ownCertificate;
    private PrivateKey ownPrivateKey;

    /**
     * Initialize certificate manager
     * @param caCertPath path of CA cert.
     * @param ownCertPath path of our own cert.
     * @param ownPrivateKeyPath path of our own private key
     */
    public CertificateManager(String caCertPath, String ownCertPath, String ownPrivateKeyPath)
            throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Loading CA cert
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream caInput = new FileInputStream(caCertPath);
        caCertificate = cf.generateCertificate(caInput);
        caInput.close();

        // Load our own cert
        FileInputStream ownCertInput = new FileInputStream(ownCertPath);
        ownCertificate = cf.generateCertificate(ownCertInput);
        ownCertInput.close();

        // Load our own private key (DER)
        FileInputStream privateKeyInput = new FileInputStream(ownPrivateKeyPath);
        byte[] privateKeyBytes = new byte[privateKeyInput.available()];
        privateKeyInput.read(privateKeyBytes);
        privateKeyInput.close();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        ownPrivateKey = keyFactory.generatePrivate(keySpec);
    }

    /**
     * Verify if certificate is signed by our trusted CA
     */
    public boolean verifyCertificate(Certificate cert) {
        try {
            cert.verify(caCertificate.getPublicKey());
            return true;
        } catch (InvalidKeyException | CertificateException | SignatureException | NoSuchAlgorithmException |
                 NoSuchProviderException e) {
            System.err.println("Certificate verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Sign data using private key
     */
    public byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(ownPrivateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verify signature using public key from specified certificate
     */
    public boolean verifySignature(byte[] data, byte[] signatureBytes, Certificate cert)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(cert.getPublicKey());
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // Getters
    public Certificate getCaCertificate() {
        return caCertificate;
    }

    public Certificate getOwnCertificate() {
        return ownCertificate;
    }

    public PrivateKey getOwnPrivateKey() {
        return ownPrivateKey;
    }

    public PublicKey getOwnPublicKey() {
        return ownCertificate.getPublicKey();
    }
}