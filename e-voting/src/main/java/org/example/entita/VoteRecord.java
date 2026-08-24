package org.example.entita;

import org.example.bulletin.MerkleProof;

import java.security.PublicKey;

public class VoteRecord {
    public enum Status { VALID, REPLACED, INVALID }

    private final byte[] ciphertext;
    private final String idc;
    private final byte[] signature;
    private final PublicKey ephemeralPublicKey;
    private final String tokenHash;
    private Status status = Status.VALID;
    private byte[] plaintext;
    private MerkleProof merkleProof;
    private byte[] signedReceipt;
    private long receiptTimestamp;

    public VoteRecord(byte[] ciphertext, String idc, byte[] signature,
                      PublicKey ephemeralPublicKey, String tokenHash) {
        this.ciphertext = ciphertext.clone();
        this.idc = idc;
        this.signature = signature.clone();
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.tokenHash = tokenHash;
    }

    public byte[] getCiphertext() { return ciphertext.clone(); }
    public String getIdc() { return idc; }
    public byte[] getSignature() { return signature.clone(); }
    public PublicKey getEphemeralPublicKey() { return ephemeralPublicKey; }
    public String getTokenHash() { return tokenHash; }
    public Status getStatus() { return status; }
    public void markReplaced() { status = Status.REPLACED; }
    public void markInvalid() { status = Status.INVALID; }
    public byte[] getPlaintext() { return plaintext == null ? null : plaintext.clone(); }
    public void setPlaintext(byte[] plaintext) { this.plaintext = plaintext.clone(); }
    public MerkleProof getMerkleProof() { return merkleProof; }
    public void setMerkleProof(MerkleProof merkleProof) { this.merkleProof = merkleProof; }
    public byte[] getSignedReceipt() { return signedReceipt == null ? null : signedReceipt.clone(); }
    public void setSignedReceipt(byte[] signedReceipt) { this.signedReceipt = signedReceipt.clone(); }
    public long getReceiptTimestamp() { return receiptTimestamp; }
    public void setReceiptTimestamp(long receiptTimestamp) { this.receiptTimestamp = receiptTimestamp; }
}
