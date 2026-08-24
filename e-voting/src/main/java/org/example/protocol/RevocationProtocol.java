package org.example.protocol;

import org.example.autorità.ElectionAutority;
import org.example.crypto.SignatureUtils;
import org.example.entità.Token;
import org.example.entità.Vote;
import org.example.entità.VoteRecord;
import org.example.entità.Voter;

import java.nio.charset.StandardCharsets;

public class RevocationProtocol {
    private final ElectionAutority ae;
    private final VotingProtocol votingProtocol = new VotingProtocol();

    public RevocationProtocol(ElectionAutority ae) {
        this.ae = ae;
    }

    public VoteRecord replaceVote(Voter voter, Token replacementToken, Vote replacementVote, String oldIdc) {
        if (replacementToken == null || replacementVote == null)
            throw new IllegalArgumentException("Dati di sostituzione incompleti");

        VoteRecord old = ae.getBulletinBoard().findByIdc(oldIdc);
        if (old == null) throw new IllegalArgumentException("Scheda originale non trovata");

        byte[] revocationMessage = (oldIdc + "|revocato").getBytes(StandardCharsets.UTF_8);
        byte[] revocationSignature = SignatureUtils.signFdh(
                revocationMessage, voter.getVote().getEphemeralPrivateKey());

        return ae.receiveReplacementVote(replacementVote, oldIdc, revocationSignature);
    }

    public static byte[] buildRevocationSignature(String oldIdc, java.security.PrivateKey originalKey) {
        return SignatureUtils.signFdh(
                (oldIdc + "|revocato").getBytes(StandardCharsets.UTF_8), originalKey);
    }
}
