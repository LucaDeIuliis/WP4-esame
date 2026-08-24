package org.example.protocol;

import org.example.autorità.ElectionAutority;
import org.example.autorità.RegistrationAutority;
import org.example.bulletin.PublicBulletinBoard;
import org.example.entità.Token;
import org.example.entità.Voter;

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
