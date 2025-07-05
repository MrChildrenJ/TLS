package protocol;

import java.io.Serializable;

public class SecureMessage implements Serializable {
    private static final long serialVersionUID = 2L;

    // Encrypted message content (includes original message and MAC)
    private byte[] encryptedContent;

    /**
     * Create secure message
     * @param encryptedContent Encrypted message content
     */
    public SecureMessage(byte[] encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    /**
     * Get encrypted message content
     */
    public byte[] getEncryptedContent() {
        return encryptedContent;
    }
}