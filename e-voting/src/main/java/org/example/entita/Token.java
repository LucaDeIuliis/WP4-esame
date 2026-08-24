package org.example.entita;

import java.util.Arrays;

public class Token {
    public enum Status { VALID, USED, INVALID }

    private final byte[] value;
    private final byte[] hash;
    private final byte[] signature;
    private Status status;

    public Token(byte[] value, byte[] hash, byte[] signature) {
        this.value = value.clone();
        this.hash = hash.clone();
        this.signature = signature.clone();
        this.status = Status.VALID;
    }

    public byte[] getValue() { return value.clone(); }
    public byte[] getHash() { return hash.clone(); }
    public byte[] getSignature() { return signature.clone(); }
    public Status getStatus() { return status; }
    public void markUsed() { status = Status.USED; }
    public void invalidate() { status = Status.INVALID; }

    @Override public String toString() {
        return "Token{hash=" + org.example.crypto.HashUtils.hex(hash) + ", status=" + status + "}";
    }

    @Override public boolean equals(Object o) {
        return o instanceof Token t && Arrays.equals(hash, t.hash);
    }
    @Override public int hashCode() { return Arrays.hashCode(hash); }
}
