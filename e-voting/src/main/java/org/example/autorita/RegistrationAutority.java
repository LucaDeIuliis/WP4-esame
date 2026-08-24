package org.example.autorita;

import org.example.crypto.HashUtils;
import org.example.crypto.SignatureUtils;
import org.example.entita.Token;
import org.example.entita.Voter;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.*;

public class RegistrationAutority {
    private final KeyPair keys;
    private final Map<String, Voter> voters = new LinkedHashMap<>();
    private final Set<String> votersWithActiveToken = new HashSet<>();
    private final Map<String, String> tokenOwner = new HashMap<>();
    private final Set<String> issuedTokenHashes = new LinkedHashSet<>();
    private final SecureRandom random = new SecureRandom();

    public RegistrationAutority(KeyPair keys) {
        this.keys = Objects.requireNonNull(keys);
    }

    public void registerVoter(Voter voter) {
        if (voters.putIfAbsent(voter.getUsername(), voter) != null)
            throw new IllegalArgumentException("Elettore già registrato");
    }

    public synchronized Token authenticateAndIssueToken(String username, String password) {
        Voter voter = authenticate(username, password);
        if (votersWithActiveToken.contains(voter.getId()))
            throw new IllegalStateException("Elettore già autorizzato con un token attivo");
        return issueToken(voter);
    }

    public synchronized Token issueReplacementToken(String username, String password) {
        Voter voter = authenticate(username, password);
        if (voter.getToken() == null || voter.getVote() == null)
            throw new IllegalStateException("Nessun voto precedente da sostituire");
        // Il vecchio token viene invalidato prima dell'emissione del nuovo, come in WP2.
        voter.getToken().invalidate();
        votersWithActiveToken.remove(voter.getId());
        return issueToken(voter);
    }

    private Token issueToken(Voter voter) {
        byte[] tokenValue = new byte[32];
        random.nextBytes(tokenValue);
        byte[] tokenHash = HashUtils.sha256(tokenValue);
        byte[] signature = SignatureUtils.signFdh(tokenHash, keys.getPrivate());
        Token token = new Token(tokenValue, tokenHash, signature);
        voter.setToken(token);
        votersWithActiveToken.add(voter.getId());
        String hashHex = HashUtils.hex(tokenHash);
        tokenOwner.put(hashHex, voter.getId());
        issuedTokenHashes.add(hashHex);
        return token;
    }

    public synchronized void markTokenConsumed(Token token) {
        String hashHex = HashUtils.hex(token.getHash());
        token.markUsed();
        votersWithActiveToken.remove(tokenOwner.get(hashHex));
    }

    private Voter authenticate(String username, String password) {
        Voter voter = voters.get(username);
        if (voter == null || !voter.checkPassword(password))
            throw new SecurityException("Credenziali non valide");
        return voter;
    }

    public KeyPair getKeys() { return keys; }
    public synchronized int getIssuedTokenCount() { return issuedTokenHashes.size(); }
    public synchronized List<String> getIssuedTokenHashes() {
        return List.copyOf(issuedTokenHashes);
    }
    public synchronized Voter getVoter(String username) { return voters.get(username); }
}
