package protocol;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;

public class HandshakeMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum MessageType {
        CLIENT_HELLO,          // Client initial message, including nonce
        SERVER_HELLO,          // Server response, including certificate and DH public key
        CLIENT_KEY_EXCHANGE,   // Client sends certificate and DH public key
        SERVER_FINISHED,       // Server sends handshake HMAC
        CLIENT_FINISHED        // Client sends handshake HMAC
    }

    private MessageType type;

    // CLIENT_HELLO
    private byte[] clientNonce;

    // SERVER_HELLO, CLIENT_KEY_EXCHANGE
    private Certificate certificate;
    private BigInteger dhPublicKey;
    private byte[] signedDhPublicKey;

    // SERVER_FINISHED, CLIENT_FINISHED
    private byte[] handshakeHmac;

    // Constructors and static factory methods

    /**
     * Create CLIENT_HELLO message
     */
    public static HandshakeMessage createClientHello(byte[] clientNonce) {
        HandshakeMessage msg = new HandshakeMessage();
        msg.type = MessageType.CLIENT_HELLO;
        msg.clientNonce = clientNonce;
        return msg;
    }

    /**
     * Create SERVER_HELLO message
     */
    public static HandshakeMessage createServerHello(
            Certificate serverCert, BigInteger dhPublicKey, byte[] signedDhPublicKey) {
        HandshakeMessage msg = new HandshakeMessage();
        msg.type = MessageType.SERVER_HELLO;
        msg.certificate = serverCert;
        msg.dhPublicKey = dhPublicKey;
        msg.signedDhPublicKey = signedDhPublicKey;
        return msg;
    }

    /**
     * Create CLIENT_KEY_EXCHANGE message
     */
    public static HandshakeMessage createClientKeyExchange(
            Certificate clientCert, BigInteger dhPublicKey, byte[] signedDhPublicKey) {
        HandshakeMessage msg = new HandshakeMessage();
        msg.type = MessageType.CLIENT_KEY_EXCHANGE;
        msg.certificate = clientCert;
        msg.dhPublicKey = dhPublicKey;
        msg.signedDhPublicKey = signedDhPublicKey;
        return msg;
    }

    /**
     * Create SERVER_FINISHED message
     */
    public static HandshakeMessage createServerFinished(byte[] handshakeHmac) {
        HandshakeMessage msg = new HandshakeMessage();
        msg.type = MessageType.SERVER_FINISHED;
        msg.handshakeHmac = handshakeHmac;
        return msg;
    }

    /**
     * Create CLIENT_FINISHED message
     */
    public static HandshakeMessage createClientFinished(byte[] handshakeHmac) {
        HandshakeMessage msg = new HandshakeMessage();
        msg.type = MessageType.CLIENT_FINISHED;
        msg.handshakeHmac = handshakeHmac;
        return msg;
    }

    // Getters
    public MessageType getType() {
        return type;
    }

    public byte[] getClientNonce() {
        return clientNonce;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public BigInteger getDhPublicKey() {
        return dhPublicKey;
    }

    public byte[] getSignedDhPublicKey() {
        return signedDhPublicKey;
    }

    public byte[] getHandshakeHmac() {
        return handshakeHmac;
    }

    // Private constructor to prevent direct instantiation
    private HandshakeMessage() {
    }
}