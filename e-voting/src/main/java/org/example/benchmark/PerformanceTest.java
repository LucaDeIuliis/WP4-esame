package org.example.benchmark;

import org.example.autorità.ElectionAutority;
import org.example.autorità.RegistrationAutority;
import org.example.bulletin.PublicBulletinBoard;
import org.example.crypto.HashUtils;
import org.example.crypto.KeyManager;
import org.example.crypto.RSAUtils;
import org.example.crypto.SignatureUtils;
import org.example.entità.Token;
import org.example.entità.Vote;
import org.example.entità.VoteRecord;
import org.example.entità.Voter;
import org.example.protocol.RegistrationProtocol;
import org.example.protocol.VotingProtocol;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class PerformanceTest {
    public record Measurement(int n, long rsaKeyGenerationNs, long rsaEncryptionNs,
                              long rsaSignatureNs, long rsaVerificationNs,
                              long merkleInsertionNs, long merkleProofVerificationNs,
                              long tallyNs, long totalNs, int messageBytes) {}

    public static List<Measurement> run(int[] sizes) {
        List<Measurement> results = new ArrayList<>();
        for (int n : sizes) results.add(runSingle(n));
        return results;
    }

    public static Measurement runSingle(int n) {
        if (n <= 0) throw new IllegalArgumentException("n deve essere positivo");

        long t0 = System.nanoTime();
        KeyPair benchmarkKeys = RSAUtils.generateKeyPair(2048);
        long keyNs = System.nanoTime() - t0;

        byte[] sample = "performance".getBytes(StandardCharsets.UTF_8);
        t0 = System.nanoTime();
        byte[] ciphertext = RSAUtils.encryptOaep(sample, benchmarkKeys.getPublic());
        long encryptionNs = System.nanoTime() - t0;

        t0 = System.nanoTime();
        byte[] signature = SignatureUtils.signFdh(ciphertext, benchmarkKeys.getPrivate());
        long signatureNs = System.nanoTime() - t0;

        t0 = System.nanoTime();
        SignatureUtils.verifyFdh(ciphertext, signature, benchmarkKeys.getPublic());
        long verificationNs = System.nanoTime() - t0;

        KeyManager km = new KeyManager(2048);
        RegistrationAutority ar = new RegistrationAutority(km.getArKeys());
        PublicBulletinBoard board = new PublicBulletinBoard();
        ElectionAutority ae = new ElectionAutority(km.getAeKeys(), km.getAeCertificateKeys(), ar, board);
        RegistrationProtocol registration = new RegistrationProtocol(ar, ae);
        VotingProtocol voting = new VotingProtocol();

        List<VoteRecord> records = new ArrayList<>();
        t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            Voter voter = new Voter("id-" + i, "user-" + i, "pw-" + i);
            ar.registerVoter(voter);
            Token token = registration.registerAndAuthorize(voter, "pw-" + i);
            Vote vote = voting.prepareVote(voter, (i & 1) == 0 ? Vote.Choice.YES : Vote.Choice.NO,
                    token, km.getAeKeys().getPublic());
            records.add(ae.receiveVote(vote));
        }
        long merkleAndProtocolNs = System.nanoTime() - t0;

        t0 = System.nanoTime();
        byte[] root = board.getMerkleTree().getRoot();
        for (VoteRecord r : records) {
            var proof = board.getMerkleTree().proofFor(r.getCiphertext());
            if (!org.example.bulletin.MerkleTree.verify(r.getCiphertext(), proof, root))
                throw new IllegalStateException("Merkle proof non valida");
        }
        long proofNs = System.nanoTime() - t0;

        // Esecuzione del tally è volutamente misurata separatamente.
        t0 = System.nanoTime();
        ae.closeAndPublishTally();
        long tallyNs = System.nanoTime() - t0;

        long totalNs = keyNs + encryptionNs + signatureNs + verificationNs
                + merkleAndProtocolNs + proofNs + tallyNs;

        VoteRecord first = records.get(0);
        int messageBytes = first.getCiphertext().length + first.getSignature().length
                + 32 + first.getEphemeralPublicKey().getEncoded().length;

        return new Measurement(n, keyNs, encryptionNs, signatureNs, verificationNs,
                merkleAndProtocolNs, proofNs, tallyNs, totalNs, messageBytes);
    }

    public static void printReport(int[] sizes) {
        System.out.println("n,keyGenMs,encryptUs,signUs,verifyUs,protocolMerkleMs,proofMs,tallyMs,totalMs,messageBytes");
        for (Measurement m : run(sizes)) {
            System.out.printf("%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d%n",
                    m.n(),
                    m.rsaKeyGenerationNs()/1_000_000.0,
                    m.rsaEncryptionNs()/1_000.0,
                    m.rsaSignatureNs()/1_000.0,
                    m.rsaVerificationNs()/1_000.0,
                    m.merkleInsertionNs()/1_000_000.0,
                    m.merkleProofVerificationNs()/1_000_000.0,
                    m.tallyNs()/1_000_000.0,
                    m.totalNs()/1_000_000.0,
                    m.messageBytes());
        }
    }
}
