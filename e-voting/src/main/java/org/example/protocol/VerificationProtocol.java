package org.example.protocol;

import org.example.autorita.ElectionAutority;
import org.example.bulletin.MerkleProof;
import org.example.bulletin.MerkleTree;
import org.example.bulletin.PublicBulletinBoard;
import org.example.crypto.HashUtils;
import org.example.crypto.RSAUtils;
import org.example.crypto.SignatureUtils;
import org.example.entita.VoteRecord;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class VerificationProtocol {
    private final ElectionAutority ae;
    private final PublicBulletinBoard board;

    public VerificationProtocol(ElectionAutority ae) {
        this.ae = ae;
        this.board = ae.getBulletinBoard();
    }

    public boolean verifyIndividual(String idc) {
        VoteRecord record = board.findByIdc(idc);
        if (record == null || record.getStatus() == VoteRecord.Status.INVALID) return false;

        PublicBulletinBoard.RootSnapshot snapshot = latestSnapshot();
        boolean rootOk = SignatureUtils.verifyFdh(
                (snapshot.rootHex() + "|" + snapshot.timestamp()).getBytes(StandardCharsets.UTF_8),
                snapshot.signature(), ae.getKeys().getPublic());
        if (!rootOk) return false;

        MerkleProof proof = board.getMerkleTree().proofFor(record.getCiphertext());
        return MerkleTree.verify(record.getCiphertext(), proof,
                hexToBytes(snapshot.rootHex()));
    }

    public boolean verifyIndividualAfterClosing(String idc, byte[] expectedId, int expectedChoice) {
        if (!verifyIndividual(idc) || !board.isClosed()) return false;
        VoteRecord record = board.findByIdc(idc);
        try {
            PrivateKey sk = decodePrivateKey(board.getAeSecretKeyEncoded());
            byte[] plaintext = RSAUtils.decryptOaep(record.getCiphertext(), sk);
            VotingProtocol.DecodedVote decoded = VotingProtocol.decode(plaintext);
            return java.util.Arrays.equals(expectedId, decoded.id())
                    && decoded.choice().getValue() == expectedChoice
                    && verifyReceipt(record);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public UniversalResult verifyUniversal() {
        if (!board.isClosed() || board.getClosingAnnouncement() == null) return new UniversalResult(false, 0, 0);

        var ann = board.getClosingAnnouncement();
        String keyB64 = Base64.getEncoder().encodeToString(ann.secretKeyEncoded());
        String msg = "chiusura|" + keyB64 + "|" + ann.rootHex() + "|" + ann.timestamp();
        boolean announcementOk = SignatureUtils.verifyFdh(
                msg.getBytes(StandardCharsets.UTF_8), ann.signature(), ae.getCertificateKeys().getPublic());
        if (!announcementOk) return new UniversalResult(false, 0, 0);

        PrivateKey sk = decodePrivateKey(ann.secretKeyEncoded());
        int yes = 0, no = 0, valid = 0;
        for (VoteRecord record : board.getRecords()) {
            if (record.getStatus() != VoteRecord.Status.VALID) continue;
            try {
                VotingProtocol.DecodedVote d = VotingProtocol.decode(
                        RSAUtils.decryptOaep(record.getCiphertext(), sk));
                if (HashUtils.sha256Hex(record.getCiphertext()).equals(record.getIdc())) {
                    if (d.choice().getValue() == 1) yes++; else no++;
                    valid++;
                }
            } catch (RuntimeException e) {
                return new UniversalResult(false, yes, no);
            }
        }
        boolean tallyOk = valid == board.getYesCount() + board.getNoCount()
                && yes == board.getYesCount() && no == board.getNoCount();
        return new UniversalResult(tallyOk, yes, no);
    }

    public boolean verifyReceipt(VoteRecord record) {
        if (record.getSignedReceipt() == null) return false;
        String message = record.getIdc() + "|" + record.getReceiptTimestamp();
        return SignatureUtils.verifyFdh(message.getBytes(StandardCharsets.UTF_8),
                record.getSignedReceipt(), ae.getKeys().getPublic());
    }

    private PublicBulletinBoard.RootSnapshot latestSnapshot() {
        var snapshots = board.getRootSnapshots();
        if (snapshots.isEmpty()) throw new IllegalStateException("Bacheca vuota");
        return snapshots.get(snapshots.size() - 1);
    }

    private static PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalStateException("Chiave privata RSA non valida", e);
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return out;
    }

    public record UniversalResult(boolean valid, int yes, int no) {}
}
