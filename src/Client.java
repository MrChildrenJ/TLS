import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import crypto.CertificateManager;
import crypto.DiffieHellman;
import crypto.KeyDerivation;
import crypto.MessageCrypto;
import protocol.HandshakeMessage;
import protocol.HandshakeMessage.MessageType;
import protocol.SecureMessage;

public class Client {
    // Configuration parameters
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8443;
    private static final String CA_CERT_PATH = "certificates/CAcertificate.pem";
    private static final String CLIENT_CERT_PATH = "certificates/CASignedClientCertificate.pem";
    private static final String CLIENT_KEY_PATH = "certificates/clientPrivateKey.der";

    // Session data
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private CertificateManager certManager;
    private DiffieHellman diffieHellman;
    private byte[] clientNonce;
    private Certificate serverCertificate;
    private BigInteger serverDHPublicKey;
    private ByteArrayOutputStream handshakeMessages;
    private KeyDerivation keyDerivation;
    private MessageCrypto serverCrypto;
    private MessageCrypto clientCrypto;
    private List<String> receivedMessages;

    /**
     * Client main method
     */
    public static void main(String[] args) {
        Client client = new Client();
        try {
            client.start();
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Start the client
     */
    public void start() throws IOException, CertificateException, NoSuchAlgorithmException,
            InvalidKeySpecException, ClassNotFoundException, InvalidKeyException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        // Initialize certificate manager
        certManager = new CertificateManager(CA_CERT_PATH, CLIENT_CERT_PATH, CLIENT_KEY_PATH);
        System.out.println("Client certificate and key loaded.");

        // Connect to server
        socket = new Socket(SERVER_HOST, SERVER_PORT);
        System.out.println("Connected to server: " + SERVER_HOST + ":" + SERVER_PORT);

        // Set up input/output streams
        out = new ObjectOutputStream(socket.getOutputStream());
        out.flush(); // Important: flush output stream first to prevent deadlock
        in = new ObjectInputStream(socket.getInputStream());

        // Initialize handshake message buffer and received message list
        handshakeMessages = new ByteArrayOutputStream();
        receivedMessages = new ArrayList<>();

        // Perform TLS handshake
        boolean handshakeSuccess = performHandshake();

        if (handshakeSuccess) {
            System.out.println("Handshake successfully completed! Now secure communication is possible.");

            // Receive server messages
            String message1 = receiveSecureMessage();
            receivedMessages.add(message1);
            System.out.println("Received server message 1: " + message1);

            String message2 = receiveSecureMessage();
            receivedMessages.add(message2);
            System.out.println("Received server message 2: " + message2);

            // Send confirmation of received messages
            StringBuilder response = new StringBuilder("Received messages from server: ");
            for (int i = 0; i < receivedMessages.size(); i++) {
                response.append("\n").append(i + 1).append(". ").append(receivedMessages.get(i));
            }
            sendSecureMessage(response.toString());

        } else {
            System.out.println("Handshake failed, terminating connection.");
        }

        // Close connection
        socket.close();
        System.out.println("Client closed.");
    }

    /**
     * Perform TLS handshake process
     */
    private boolean performHandshake() {
        try {
            // Step 1: Generate client nonce and send client Hello
            SecureRandom random = new SecureRandom();
            clientNonce = new byte[32];
            random.nextBytes(clientNonce);

            HandshakeMessage clientHello = HandshakeMessage.createClientHello(clientNonce);
            out.writeObject(clientHello);
            out.flush();

            // Record handshake message
            byte[] clientHelloBytes = serializeMessage(clientHello);
            handshakeMessages.write(clientHelloBytes);

            System.out.println("Sent client Hello message and nonce");

            // Step 2: Receive server Hello, including certificate and DH public key
            HandshakeMessage serverHello = (HandshakeMessage) in.readObject();
            if (serverHello.getType() != MessageType.SERVER_HELLO) {
                System.err.println("Handshake error: Expected SERVER_HELLO but received " + serverHello.getType());
                return false;
            }

            // Record handshake message
            byte[] serverHelloBytes = serializeMessage(serverHello);
            handshakeMessages.write(serverHelloBytes);

            // Verify server certificate
            serverCertificate = serverHello.getCertificate();
            if (!certManager.verifyCertificate(serverCertificate)) {
                System.err.println("Server certificate verification failed");
                return false;
            }

            // Get and verify server DH public key
            serverDHPublicKey = serverHello.getDhPublicKey();
            byte[] serverDHPublicKeyBytes = serverDHPublicKey.toByteArray();
            byte[] signedServerDHPublicKey = serverHello.getSignedDhPublicKey();

            // Verify server DH public key signature
            boolean validSignature = false;
            try {
                validSignature = certManager.verifySignature(
                        serverDHPublicKeyBytes, signedServerDHPublicKey, serverCertificate);
            } catch (Exception e) {
                System.err.println("Error when verifying server DH public key signature: " + e.getMessage());
                return false;
            }

            if (!validSignature) {
                System.err.println("Server DH public key signature verification failed");
                return false;
            }

            System.out.println("Server certificate and DH public key verified");

            // Step 3: Generate client DH key pair and send client key exchange
            diffieHellman = new DiffieHellman();
            BigInteger clientDHPublicKey = diffieHellman.getPublicKey();

            // Sign DH public key using client private key
            byte[] clientDHPublicKeyBytes = clientDHPublicKey.toByteArray();
            byte[] signedClientDHPublicKey = certManager.sign(clientDHPublicKeyBytes);

            // Create and send client key exchange message
            HandshakeMessage clientKeyExchange = HandshakeMessage.createClientKeyExchange(
                    certManager.getOwnCertificate(), clientDHPublicKey, signedClientDHPublicKey);
            out.writeObject(clientKeyExchange);
            out.flush();

            // Record handshake message
            byte[] clientKeyExchangeBytes = serializeMessage(clientKeyExchange);
            handshakeMessages.write(clientKeyExchangeBytes);

            System.out.println("Sent client key exchange message, including certificate and DH public key");

            // Calculate DH shared secret and generate session keys
            byte[] dhSharedSecret = diffieHellman.computeSharedSecret(serverDHPublicKey);
            keyDerivation = new KeyDerivation(clientNonce, dhSharedSecret);

            // Create encryption tools
            serverCrypto = new MessageCrypto(
                    keyDerivation.getServerEncryptKey(),
                    keyDerivation.getServerMacKey(),
                    keyDerivation.getServerIv());

            clientCrypto = new MessageCrypto(
                    keyDerivation.getClientEncryptKey(),
                    keyDerivation.getClientMacKey(),
                    keyDerivation.getClientIv());

            System.out.println("Calculated shared key and generated session keys");

            // Step 4: Receive server finished message
            HandshakeMessage serverFinished = (HandshakeMessage) in.readObject();
            if (serverFinished.getType() != MessageType.SERVER_FINISHED) {
                System.err.println("Handshake error: Expected SERVER_FINISHED but received " + serverFinished.getType());
                return false;
            }

            // Save handshake state before adding server finished message
            byte[] handshakeDataBeforeServerFinished = handshakeMessages.toByteArray();

            // Record handshake message
            byte[] serverFinishedBytes = serializeMessage(serverFinished);
            handshakeMessages.write(serverFinishedBytes);

            // Verify server HMAC - using handshake data up to but not including SERVER_FINISHED
            byte[] serverFinishedHmac = serverFinished.getHandshakeHmac();
            byte[] expectedServerHmac = serverCrypto.generateHandshakeMAC(handshakeDataBeforeServerFinished);

            if (!Arrays.equals(serverFinishedHmac, expectedServerHmac)) {
                System.err.println("Server finished message HMAC verification failed");
                return false;
            }

            System.out.println("Server finished message HMAC verified");

            // Step 5: Generate and send client finished message - using same data as server used to verify
            byte[] clientFinishedHmac = clientCrypto.generateHandshakeMAC(handshakeDataBeforeServerFinished);
            HandshakeMessage clientFinished = HandshakeMessage.createClientFinished(clientFinishedHmac);
            out.writeObject(clientFinished);
            out.flush();

            System.out.println("Sent client finished message");

            return true;

        } catch (Exception e) {
            System.err.println("Error during handshake process: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Send encrypted message
     */
    private void sendSecureMessage(String message) throws IOException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        byte[] messageBytes = message.getBytes();
        byte[] encryptedMessage = clientCrypto.encryptAndAuthenticate(messageBytes);
        SecureMessage secureMessage = new SecureMessage(encryptedMessage);

        out.writeObject(secureMessage);
        out.flush();
        System.out.println("Sent encrypted message: " + message);
    }

    /**
     * Receive and decrypt message
     */
    private String receiveSecureMessage() throws ClassNotFoundException, IOException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        SecureMessage secureMessage = (SecureMessage) in.readObject();
        byte[] encryptedContent = secureMessage.getEncryptedContent();
        byte[] decryptedMessage = serverCrypto.decryptAndVerify(encryptedContent);

        if (decryptedMessage == null) {
            throw new SecurityException("Message authentication failed");
        }

        String message = new String(decryptedMessage);
        System.out.println("Received and decrypted message");
        return message;
    }

    /**
     * Serialize message object to byte array
     */
    private byte[] serializeMessage(Object message) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
        objectStream.writeObject(message);
        objectStream.flush();
        return byteStream.toByteArray();
    }
}