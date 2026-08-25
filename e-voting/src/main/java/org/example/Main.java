package org.example;

import org.example.autorita.ElectionAutority;
import org.example.autorita.RegistrationAutority;
import org.example.bulletin.PublicBulletinBoard;
import org.example.benchmark.PerformanceTest;
import org.example.crypto.KeyManager;
import org.example.entita.Token;
import org.example.entita.Vote;
import org.example.entita.VoteRecord;
import org.example.entita.Voter;
import org.example.protocol.RegistrationProtocol;
import org.example.protocol.RevocationProtocol;
import org.example.protocol.VerificationProtocol;
import org.example.protocol.VotingProtocol;

import java.util.List;

public class Main {
    public static void main(String[] args) {
        KeyManager keys = new KeyManager(2048);

        RegistrationAutority ar = new RegistrationAutority(keys.getArKeys());
        PublicBulletinBoard board = new PublicBulletinBoard();
        ElectionAutority ae = new ElectionAutority(
                keys.getAeKeys(), keys.getAeCertificateKeys(), ar, board);
        VerificationProtocol verification = new VerificationProtocol(ae);
        RegistrationProtocol registration = new RegistrationProtocol(ar, ae);
        VotingProtocol voting = new VotingProtocol();

        // Elettori di esempio.
        Voter alice = new Voter("v1", "alice", "alice123");
        Voter bob = new Voter("v2", "bob", "bob123");
        Voter carol = new Voter("v3", "carol", "carol123");
        ar.registerVoter(alice);
        ar.registerVoter(bob);
        ar.registerVoter(carol);

        // Fase di registrazione + voto.
        Token aliceToken = registration.registerAndAuthorize(alice, "alice123");
        Vote aliceVote = voting.prepareVote(alice, Vote.Choice.YES, aliceToken, keys.getAeKeys().getPublic());
        VoteRecord aliceRecord = ae.receiveVote(aliceVote);
        alice.setVote(aliceVote);

        Token bobToken = registration.registerAndAuthorize(bob, "bob123");
        Vote bobVote = voting.prepareVote(bob, Vote.Choice.NO, bobToken, keys.getAeKeys().getPublic());
        VoteRecord bobRecord = ae.receiveVote(bobVote);
        bob.setVote(bobVote);

        Token carolToken = registration.registerAndAuthorize(carol, "carol123");
        Vote carolVote = voting.prepareVote(carol, Vote.Choice.YES, carolToken, keys.getAeKeys().getPublic());
        VoteRecord carolRecord = ae.receiveVote(carolVote);
        carol.setVote(carolVote);

        // Sostituzione del voto di Carol prima della chiusura.
        Token replacementToken = registration.replaceAuthorization(carol, "carol123");
        Vote replacementVote = voting.prepareVote(
                carol, Vote.Choice.NO, replacementToken, keys.getAeKeys().getPublic());
        RevocationProtocol revocation = new RevocationProtocol(ae);
        VoteRecord replacementRecord = revocation.replaceVote(
                carol, replacementToken, replacementVote, carolRecord.getIdc());
        boolean oldCarolVoteRejected =
                !verification.verifyIndividual(carolRecord.getIdc());
        carol.setVote(replacementVote);

        // Chiusura, pubblicazione della chiave e scrutinio.
        ae.closeAndPublishTally();
        // Come previsto dal WP2, la chiave effimera non serve più dopo la chiusura.
        aliceVote.destroyEphemeralPrivateKey();
        bobVote.destroyEphemeralPrivateKey();
        carolVote.destroyEphemeralPrivateKey();
        replacementVote.destroyEphemeralPrivateKey();
        VerificationProtocol.UniversalResult universal = verification.verifyUniversal();

        System.out.println("=== WP4 e-voting ===");
        System.out.println("Schede pubblicate: " + board.getRecords().size());
        System.out.println("Token emessi: " + board.getTokenCountPublished());
        System.out.println("Coerenza token/schede: " + board.hasValidTokenCount());
        System.out.println("Risultato: YES=" + board.getYesCount() + ", NO=" + board.getNoCount());
        System.out.println("Root finale: " + board.getFinalRootHex());
        System.out.println("Verifica universale: " + universal.valid());
        System.out.println("Vecchio voto Carol non verificabile dopo sostituzione: " + oldCarolVoteRejected);

        boolean aliceVerified = verification.verifyIndividualAfterClosing(
                aliceRecord.getIdc(), alice.getVote().getId(), alice.getVote().getChoice().getValue());
        boolean bobVerified = verification.verifyIndividualAfterClosing(
                bobRecord.getIdc(), bob.getVote().getId(), bob.getVote().getChoice().getValue());
        boolean receiptVerified = verification.verifyReceipt(replacementRecord);

        System.out.println("Verifica individuale Alice: " + aliceVerified);
        System.out.println("Verifica individuale Bob: " + bobVerified);
        System.out.println("Ricevuta firmata AE (miglioramento WP3): " + receiptVerified);

        // Per una prima esecuzione si mantiene il benchmark leggero.
        if (args.length > 0 && args[0].equalsIgnoreCase("benchmark")) {
            int[] sizes = new int[args.length - 1];
            for (int i = 1; i < args.length; i++) sizes[i - 1] = Integer.parseInt(args[i]);
            if (sizes.length == 0) sizes = new int[]{10};
            PerformanceTest.printReport(sizes);
        }
    }
}
