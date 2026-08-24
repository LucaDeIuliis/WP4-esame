package org.example.entita;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class Vote {
    public enum Choice {
        NO(0), YES(1);
        private final int value;
        Choice(int value) { this.value = value; }
        public int getValue() { return value; }
        public static Choice fromInt(int value) {
            return value == 0 ? NO : value == 1 ? YES : null;
        }
    }

    private final Choice choice;
    private final byte[] id;
    private final byte[] ciphertext;
    private final Token token;
    private final PublicKey ephemeralPublicKey;
    private PrivateKey ephemeralPrivateKey;
    private final byte[] signature;

    public Vote(Choice choice, byte[] id, byte[] ciphertext, Token token,
                PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, byte[] signature) {
        this.choice = choice;
        this.id = id.clone();
        this.ciphertext = ciphertext.clone();
        this.token = token;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.signature = signature.clone();
    }

    public Choice getChoice() { return choice; }
    public byte[] getId() { return id.clone(); }
    public byte[] getCiphertext() { return ciphertext.clone(); }
    public Token getToken() { return token; }
    public PublicKey getEphemeralPublicKey() { return ephemeralPublicKey; }
    public PrivateKey getEphemeralPrivateKey() { return ephemeralPrivateKey; }
    public void destroyEphemeralPrivateKey() { this.ephemeralPrivateKey = null; }
    public byte[] getSignature() { return signature.clone(); }

    public String getCiphertextId() {
        return org.example.crypto.HashUtils.sha256Hex(ciphertext);
    }
}
