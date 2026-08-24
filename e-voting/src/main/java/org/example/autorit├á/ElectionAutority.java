package org.example.autorità;

import org.example.bulletin.PublicBulletinBoard;
import org.example.crypto.HashUtils;
import org.example.crypto.SignatureUtils;
import org.example.entità.Token;
import org.example.entità.Vote;
import org.example.entità.VoteRecord;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ElectionAutority {
    private final KeyPair keys;
    private final KeyPair certificateKeys;
    private final RegistrationAutority registrationAutority;
    private final PublicBulletinBoard bulletinBoard;

    // Registro delle autorizzazioni: hash(token) -> token non ancora consumato.
    private final Map<String, Token> authorizedTokens = new ConcurrentHashMap<>();
    private final Set<String> consumedTokens = ConcurrentHashMap.newKeySet();

    public ElectionAutority(KeyPair keys, KeyPair certificateKeys,
                            RegistrationAutority registrationAutority,
                            PublicBulletinBoard bulletinBoard) {
        this.keys = Objects.requireNonNull(keys);
        this.certificateKeys = Objects.requireNonNull(certificateKeys);
        this.registrationAutority = Objects.requireNonNull(registrationAutority);
        this.bulletinBoard = Objects.requireNonNull(bulletinBoard);
    }

    public synchronized void authorizeToken(byte[] tokenHash, byte[] signature) {
        if (!SignatureUtils.verifyFdh(tokenHash, signature, registrationAutority.getKeys().getPublic()))
            throw new SecurityException("Firma del token non valida");
        String hashHex = HashUtils.hex(tokenHash);
        if (consumedTokens.contains(hashHex) || authorizedTokens.containsKey(hashHex))
            throw new SecurityException("Token già registrato o consumato");
        authorizedTokens.put(hashHex, new Token(new byte[0], tokenHash, signature));
    }

    public synchronized VoteRecord receiveVote(Vote vote) {
        ensureOpen();
        String tokenHash = HashUtils.hex(HashUtils.sha256(vote.getToken().getValue()));
        if (consumedTokens.contains(tokenHash) || !authorizedTokens.containsKey(tokenHash))
            throw new SecurityException("Token non valido o già consumato");

        byte[] signedMessage = concat(vote.getCiphertext(), vote.getToken().getValue());
        if (!SignatureUtils.verifyFdh(signedMessage, vote.getSignature(), vote.getEphemeralPublicKey()))
            throw new SecurityException("Firma della scheda non valida");

        // Atomicità: il controllo e il consumo del token avvengono nello stesso monitor.
        authorizedTokens.remove(tokenHash);
        consumedTokens.add(tokenHash);
        registrationAutority.markTokenConsumed(vote.getToken());

        String idc = HashUtils.sha256Hex(vote.getCiphertext());
        VoteRecord record = new VoteRecord(vote.getCiphertext(), idc, vote.getSignature(),
                vote.getEphemeralPublicKey(), tokenHash);
        bulletinBoard.publishVote(record, keys.getPrivate());
        long receiptTimestamp = Instant.now().toEpochMilli();
        byte[] receiptMessage = (idc + "|" + receiptTimestamp).getBytes(StandardCharsets.UTF_8);
        record.setReceiptTimestamp(receiptTimestamp);
        record.setSignedReceipt(SignatureUtils.signFdh(receiptMessage, keys.getPrivate()));

        return record;
    }

    public synchronized void closeAndPublishTally() {
        ensureOpen();
        org.example.protocol.TallyProtocol tally = new org.example.protocol.TallyProtocol(this, bulletinBoard);
        tally.execute();
    }

    public synchronized VoteRecord receiveReplacementVote(Vote replacementVote, String oldIdc,
                                                           byte[] revocationSignature) {
        ensureOpen();
        VoteRecord old = bulletinBoard.findByIdc(oldIdc);
        if (old == null || old.getStatus() != VoteRecord.Status.VALID)
            throw new IllegalArgumentException("Scheda originale non sostituibile");

        byte[] revocationMessage = (oldIdc + "|revocato").getBytes(StandardCharsets.UTF_8);
        if (!SignatureUtils.verifyFdh(revocationMessage, revocationSignature, old.getEphemeralPublicKey()))
            throw new SecurityException("Firma di revoca non valida");

        // Validazione completa del nuovo voto prima di modificare lo stato del vecchio.
        String tokenHash = HashUtils.hex(HashUtils.sha256(replacementVote.getToken().getValue()));
        if (consumedTokens.contains(tokenHash) || !authorizedTokens.containsKey(tokenHash))
            throw new SecurityException("Token sostitutivo non valido o già consumato");
        byte[] signedMessage = concat(replacementVote.getCiphertext(), replacementVote.getToken().getValue());
        if (!SignatureUtils.verifyFdh(signedMessage, replacementVote.getSignature(),
                replacementVote.getEphemeralPublicKey()))
            throw new SecurityException("Firma della scheda sostitutiva non valida");

        authorizedTokens.remove(tokenHash);
        consumedTokens.add(tokenHash);
        registrationAutority.markTokenConsumed(replacementVote.getToken());

        old.markReplaced();
        String markMessage = oldIdc + "|sostituita";
        byte[] markSignature = SignatureUtils.signFdh(
                markMessage.getBytes(StandardCharsets.UTF_8), keys.getPrivate());
        bulletinBoard.markReplaced(oldIdc, HashUtils.hex(markSignature));

        VoteRecord replacement = new VoteRecord(
                replacementVote.getCiphertext(),
                HashUtils.sha256Hex(replacementVote.getCiphertext()),
                replacementVote.getSignature(),
                replacementVote.getEphemeralPublicKey(),
                tokenHash);
        bulletinBoard.publishVote(replacement, keys.getPrivate());

        long receiptTimestamp = Instant.now().toEpochMilli();
        replacement.setReceiptTimestamp(receiptTimestamp);
        replacement.setSignedReceipt(SignatureUtils.signFdh(
                (replacement.getIdc() + "|" + receiptTimestamp).getBytes(StandardCharsets.UTF_8),
                keys.getPrivate()));
        return replacement;
    }

    public synchronized KeyPair getKeys() { return keys; }
    public synchronized KeyPair getCertificateKeys() { return certificateKeys; }
    public RegistrationAutority getRegistrationAutority() { return registrationAutority; }
    public PublicBulletinBoard getBulletinBoard() { return bulletinBoard; }
    public Map<String, Token> getAuthorizedTokens() { return Collections.unmodifiableMap(authorizedTokens); }

    public synchronized byte[] buildClosingAnnouncement(String rootHex, long timestamp) {
        String message = "chiusura|" + java.util.Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded())
                + "|" + rootHex + "|" + timestamp;
        return SignatureUtils.signFdh(message.getBytes(StandardCharsets.UTF_8), certificateKeys.getPrivate());
    }

    private void ensureOpen() {
        if (bulletinBoard.isClosed()) throw new IllegalStateException("Urne chiuse");
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
