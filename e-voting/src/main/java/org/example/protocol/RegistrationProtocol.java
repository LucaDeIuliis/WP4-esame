package org.example.protocol;

import org.example.autorita.ElectionAutority;
import org.example.autorita.RegistrationAutority;
import org.example.bulletin.PublicBulletinBoard;
import org.example.entita.Token;
import org.example.entita.Voter;

public class RegistrationProtocol {
    private final RegistrationAutority ar;
    private final ElectionAutority ae;

    public RegistrationProtocol(RegistrationAutority ar, ElectionAutority ae) {
        this.ar = ar;
        this.ae = ae;
    }

    public Token registerAndAuthorize(Voter voter, String password) {
        Token token = ar.authenticateAndIssueToken(voter.getUsername(), password);
        ae.authorizeToken(token.getHash(), token.getSignature());
        return token;
    }

    public Token replaceAuthorization(Voter voter, String password) {
        Token token = ar.issueReplacementToken(voter.getUsername(), password);
        ae.authorizeToken(token.getHash(), token.getSignature());
        return token;
    }
}
