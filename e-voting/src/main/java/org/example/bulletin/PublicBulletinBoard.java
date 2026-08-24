package org.example.bulletin;

import org.example.crypto.HashUtils;
import org.example.crypto.SignatureUtils;
import org.example.entità.VoteRecord;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PublicBulletinBoard {
    public record RootSnapshot(String rootHex, long timestamp, byte[] signature) {
        public RootSnapshot {
            signature = signature.clone();
        }
        @Override public byte[] signature() { return signature.clone(); }
    }

    public record ClosingAnnouncement(byte[] secretKeyEncoded, String rootHex, long timestamp, byte[] signature) {
        public ClosingAnnouncement {
            secretKeyEncoded = secretKeyEncoded.clone();
            signature = signature.clone();
        }
        @Override public byte[] secretKeyEncoded() { return secretKeyEncoded.clone(); }
        @Override public byte[] signature() { return signature.clone(); }
    }

    private final List<VoteRecord> records = new ArrayList<>();
    private final MerkleTree merkleTree = new MerkleTree();
    private final List<RootSnapshot> rootSnapshots = new ArrayList<>();
    private final Map<String, String> replacementMarks = new LinkedHashMap<>();
    private final List<String> tokenHashesPublished = new ArrayList<>();

    private String finalRootHex;
    private byte[] aeSecretKeyEncoded;
    private ClosingAnnouncement closingAnnouncement;
    private int yesCount;
    private int noCount;
    private boolean closed;

    public synchronized void publishVote(VoteRecord record, PrivateKey aeSigningKey) {
        if (closed) throw new IllegalStateException("Urne già chiuse");
        records.add(record);
        merkleTree.addLeaf(record.getCiphertext());
        signCurrentRoot(aeSigningKey);
        record.setMerkleProof(merkleTree.proofFor(record.getCiphertext()));
    }

    public synchronized void publishTokenCount(int count) {
        tokenHashesPublished.clear();
        for (int i = 0; i < count; i++) tokenHashesPublished.add("token-" + i);
    }

    public synchronized void publishTokenHashes(List<String> hashes) {
        tokenHashesPublished.clear();
        tokenHashesPublished.addAll(hashes);
    }

    public synchronized void markReplaced(String oldIdc, String markSignatureHex) {
        replacementMarks.put(oldIdc, markSignatureHex);
    }

    public synchronized void close(byte[] secretKeyEncoded, String rootHex,
                                   long timestamp, byte[] closingSignature) {
        if (closed) throw new IllegalStateException("Urne già chiuse");
        this.closed = true;
        this.finalRootHex = rootHex;
        this.aeSecretKeyEncoded = secretKeyEncoded.clone();
        this.closingAnnouncement = new ClosingAnnouncement(secretKeyEncoded, rootHex, timestamp, closingSignature);
    }

    public synchronized void publishTally(List<VoteRecord> validRecords, int yes, int no) {
        this.yesCount = yes;
        this.noCount = no;
        for (VoteRecord r : validRecords) {
            // plaintext has already been verified by TallyProtocol
        }
    }

    private void signCurrentRoot(PrivateKey key) {
        long timestamp = Instant.now().toEpochMilli();
        String message = HashUtils.hex(merkleTree.getRoot()) + "|" + timestamp;
        byte[] signature = SignatureUtils.signFdh(message.getBytes(StandardCharsets.UTF_8), key);
        rootSnapshots.add(new RootSnapshot(HashUtils.hex(merkleTree.getRoot()), timestamp, signature));
    }

    public synchronized List<VoteRecord> getRecords() {
        return Collections.unmodifiableList(new ArrayList<>(records));
    }

    public synchronized VoteRecord findByIdc(String idc) {
        return records.stream().filter(r -> r.getIdc().equals(idc)).findFirst().orElse(null);
    }

    public synchronized MerkleTree getMerkleTree() { return merkleTree; }
    public synchronized String getCurrentRootHex() { return HashUtils.hex(merkleTree.getRoot()); }
    public synchronized String getFinalRootHex() { return finalRootHex; }
    public synchronized List<RootSnapshot> getRootSnapshots() {
        return Collections.unmodifiableList(new ArrayList<>(rootSnapshots));
    }
    public synchronized List<String> getTokenHashesPublished() {
        return Collections.unmodifiableList(new ArrayList<>(tokenHashesPublished));
    }
    public synchronized Map<String,String> getReplacementMarks() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(replacementMarks));
    }
    public synchronized ClosingAnnouncement getClosingAnnouncement() { return closingAnnouncement; }
    public synchronized byte[] getAeSecretKeyEncoded() {
        return aeSecretKeyEncoded == null ? null : aeSecretKeyEncoded.clone();
    }
    public synchronized int getYesCount() { return yesCount; }
    public synchronized int getNoCount() { return noCount; }
    public synchronized boolean isClosed() { return closed; }
}
