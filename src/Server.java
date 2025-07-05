import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import crypto.CertificateManager;
import crypto.DiffieHellman;
import crypto.KeyDerivation;
import crypto.MessageCrypto;
import protocol.HandshakeMessage;
import protocol.HandshakeMessage.MessageType;
import protocol.SecureMessage;

public class Server {
    // Configuration parameters
    private static final int PORT = 8443;
    private static final String CA_CERT_PATH = "certificates/CAcertificate.pem";
    private static final String SERVER_CERT_PATH = "certificates/CASignedServerCertificate.pem";
    private static final String SERVER_KEY_PATH = "certificates/serverPrivateKey.der";

    // Session data
    private Socket clientSocket;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private CertificateManager certManager;
    private DiffieHellman diffieHellman;
    private byte[] clientNonce;
    private Certificate clientCertificate;
    private BigInteger clientDHPublicKey;
    private ByteArrayOutputStream handshakeMessages;
    private KeyDerivation keyDerivation;
    private MessageCrypto serverCrypto;
    private MessageCrypto clientCrypto;

    /**
     * Server main method
     */
    public static void main(String[] args) {
        Server server = new Server();
        try {
            server.start();
        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Start the server
     */
    public void start() throws IOException, CertificateException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {

        // Initialize certificate manager
        certManager = new CertificateManager(CA_CERT_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH);
        System.out.println("Server certificate and key have been loaded.");

        // Create server socket
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server is running on port " + PORT);

        // Wait for client connection
        clientSocket = serverSocket.accept();
        System.out.println("Client is connectted from: " + clientSocket.getInetAddress());

        // Set up input/output streams
        out = new ObjectOutputStream(clientSocket.getOutputStream());
        out.flush(); // Important: flush output stream first to prevent deadlock
        in = new ObjectInputStream(clientSocket.getInputStream());

        // Initialize handshake message buffer
        handshakeMessages = new ByteArrayOutputStream();

        // Perform TLS handshake
        boolean handshakeSuccess = performHandshake();

        if (handshakeSuccess) {
            System.out.println("Handshake successfully completed! Secure communication can now begin.");

            // Send test messages
            sendSecureMessage("This is the 1st test message from server.");
            sendSecureMessage("This is the 2nd test message from server.");

            // Receive client response
            String response = receiveSecureMessage();
            System.out.println("Receive client response: " + response);
        } else {
            System.out.println("Handshake failed, stop connection.");
        }

        // Close connection
        clientSocket.close();
        serverSocket.close();
        System.out.println("Server has shut down.");
    }

    /**
     * Perform TLS handshake process
     */
    private boolean performHandshake() {
        try {
            // Step 1: Receive client Hello message, including nonce
            HandshakeMessage clientHello = (HandshakeMessage) in.readObject();
            if (clientHello.getType() != MessageType.CLIENT_HELLO) {
                System.err.println("Handshake error: Expected CLIENT_HELLO but received " + clientHello.getType());
                return false;
            }

            // Record handshake message
            byte[] clientHelloBytes = serializeMessage(clientHello);
            handshakeMessages.write(clientHelloBytes);

            // Save client nonce
            clientNonce = clientHello.getClientNonce();
            System.out.println("Receive Hello and nonce from Client");

            // Step 2: Generate DH key pair and send server Hello
            diffieHellman = new DiffieHellman();
            BigInteger serverDHPublicKey = diffieHellman.getPublicKey();

            // Sign DH public key using server private key
            byte[] serverDHPublicKeyBytes = serverDHPublicKey.toByteArray();
            byte[] signedDHPublicKey = certManager.sign(serverDHPublicKeyBytes);

            // Create and send server Hello message
            HandshakeMessage serverHello = HandshakeMessage.createServerHello(
                    certManager.getOwnCertificate(), serverDHPublicKey, signedDHPublicKey);
            out.writeObject(serverHello);
            out.flush();

            // Record handshake message
            byte[] serverHelloBytes = serializeMessage(serverHello);
            handshakeMessages.write(serverHelloBytes);

            System.out.println("Send Server's Hello, including certificate and public key.");

            // Step 3: Receive client key exchange message
            HandshakeMessage clientKeyExchange = (HandshakeMessage) in.readObject();
            if (clientKeyExchange.getType() != MessageType.CLIENT_KEY_EXCHANGE) {
                System.err.println("Handshake error: Expected CLIENT_KEY_EXCHANGE but received " + clientKeyExchange.getType());
                return false;
            }

            // Record handshake message
            byte[] clientKeyExchangeBytes = serializeMessage(clientKeyExchange);
            handshakeMessages.write(clientKeyExchangeBytes);

            // Verify client certificate
            clientCertificate = clientKeyExchange.getCertificate();
            if (!certManager.verifyCertificate(clientCertificate)) {
                System.err.println("Client certificate verification failed.");
                return false;
            }

            // Get and verify client DH public key
            clientDHPublicKey = clientKeyExchange.getDhPublicKey();
            byte[] clientDHPublicKeyBytes = clientDHPublicKey.toByteArray();
            byte[] signedClientDHPublicKey = clientKeyExchange.getSignedDhPublicKey();

            // Verify client DH public key signature
            boolean validSignature = false;
            try {
                validSignature = certManager.verifySignature(
                        clientDHPublicKeyBytes, signedClientDHPublicKey, clientCertificate);
            } catch (Exception e) {
                System.err.println("Error verifying the client’s DH public key signature: " + e.getMessage());
                return false;
            }

            if (!validSignature) {
                System.err.println("Client’s DH public key signature verification failed.");
                return false;
            }

            System.out.println("Client certificate and DH public key have been verified.");

            // Calculate DH shared secret and generate session keys
            byte[] dhSharedSecret = diffieHellman.computeSharedSecret(clientDHPublicKey);
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

            System.out.println("Shared key has been calculated and session key generated.");

            // Step 4: Generate and send server finished message
            byte[] handshakeDataForServerFinish = handshakeMessages.toByteArray();
            byte[] serverFinishedHmac = serverCrypto.generateHandshakeMAC(handshakeDataForServerFinish);
            HandshakeMessage serverFinished = HandshakeMessage.createServerFinished(serverFinishedHmac);
            out.writeObject(serverFinished);
            out.flush();

            // Record handshake message
            byte[] serverFinishedBytes = serializeMessage(serverFinished);
            handshakeMessages.write(serverFinishedBytes);

            System.out.println("Sending server completion message.");

            // Step 5: Receive client finished message
            HandshakeMessage clientFinished = (HandshakeMessage) in.readObject();
            if (clientFinished.getType() != MessageType.CLIENT_FINISHED) {
                System.err.println("Handshake error: Expected CLIENT_FINISHED but received " + clientFinished.getType());
                return false;
            }

            // Verify client HMAC - use the handshake data up to and including the SERVER_FINISHED message
            byte[] clientFinishedHmac = clientFinished.getHandshakeHmac();
            byte[] expectedClientHmac = clientCrypto.generateHandshakeMAC(handshakeDataForServerFinish);

            if (!Arrays.equals(clientFinishedHmac, expectedClientHmac)) {
                System.err.println("Client’s Finished message HMAC verification failed.");
                return false;
            }

            System.out.println("Client’s Finished message HMAC has been verified.");

            return true;

        } catch (Exception e) {
            System.err.println("Error during the handshake process: " + e.getMessage());
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
        byte[] encryptedMessage = serverCrypto.encryptAndAuthenticate(messageBytes);
        SecureMessage secureMessage = new SecureMessage(encryptedMessage);

        out.writeObject(secureMessage);
        out.flush();
        System.out.println("Encrypted message has been sent: " + message);
    }

    /**
     * Receive and decrypt message
     */
    private String receiveSecureMessage() throws ClassNotFoundException, IOException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        SecureMessage secureMessage = (SecureMessage) in.readObject();
        byte[] encryptedContent = secureMessage.getEncryptedContent();
        byte[] decryptedMessage = clientCrypto.decryptAndVerify(encryptedContent);

        if (decryptedMessage == null) {
            throw new SecurityException("Message authentication failed.");
        }

        String message = new String(decryptedMessage);
        System.out.println("Message has been received and decrypted.");
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