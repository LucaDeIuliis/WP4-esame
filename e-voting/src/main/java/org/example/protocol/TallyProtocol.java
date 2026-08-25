package org.example.protocol;

import org.example.autorita.ElectionAutority;
import org.example.bulletin.PublicBulletinBoard;
import org.example.crypto.RSAUtils;
import org.example.crypto.SignatureUtils;
import org.example.entita.VoteRecord;

import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TallyProtocol {
    private final ElectionAutority ae;
    private final PublicBulletinBoard board;

    public TallyProtocol(ElectionAutority ae, PublicBulletinBoard board) {
        this.ae = ae;
        this.board = board;
    }

    public Result execute() {
        if (board.isClosed()) throw new IllegalStateException("Scrutinio già eseguito");

        String finalRoot = board.getCurrentRootHex();
        long timestamp = Instant.now().toEpochMilli();
        PrivateKey skAE = ae.getKeys().getPrivate();

        String keyB64 = Base64.getEncoder().encodeToString(skAE.getEncoded());
        String announcementMessage = "chiusura|" + keyB64 + "|" + finalRoot + "|" + timestamp;
        byte[] announcementSignature = SignatureUtils.signFdh(
                announcementMessage.getBytes(StandardCharsets.UTF_8),
                ae.getCertificateKeys().getPrivate());

        int issuedTokenCount =
                ae.getRegistrationAutority().getIssuedTokenCount();

        board.publishTokenCount(issuedTokenCount);

        if (!board.hasValidTokenCount()) {
            throw new SecurityException(
                    "Numero di schede pubblicate superiore al numero di token emessi");
        }

        board.close(
                skAE.getEncoded(),
                finalRoot,
                timestamp,
                announcementSignature
        );

        List<VoteRecord> counted = new ArrayList<>();
        int yes = 0, no = 0;
        for (VoteRecord record : board.getRecords()) {
            if (record.getStatus() != VoteRecord.Status.VALID) continue;
            try {
                byte[] plaintext = RSAUtils.decryptOaep(record.getCiphertext(), skAE);
                VotingProtocol.DecodedVote decoded = VotingProtocol.decode(plaintext);
                if (!org.example.crypto.HashUtils.sha256Hex(record.getCiphertext()).equals(record.getIdc()))
                    throw new IllegalArgumentException("idc incoerente");
                record.setPlaintext(plaintext);
                counted.add(record);
                if (decoded.choice() == org.example.entita.Vote.Choice.YES) yes++;
                else no++;
            } catch (RuntimeException ex) {
                record.markInvalid();
            }
        }
        board.publishTally(counted, yes, no);
        return new Result(yes, no, yes + no);
    }

    public record Result(int yes, int no, int total) {}
}
