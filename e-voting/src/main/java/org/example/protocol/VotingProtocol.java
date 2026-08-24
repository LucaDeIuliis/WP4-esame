package org.example.protocol;

import org.example.crypto.RSAUtils;
import org.example.crypto.SignatureUtils;
import org.example.entità.Token;
import org.example.entità.Vote;
import org.example.entità.Voter;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;

public class VotingProtocol {
    private final SecureRandom random = new SecureRandom();

    public Vote prepareVote(Voter voter, Vote.Choice choice, Token token, java.security.PublicKey aePublicKey) {
        if (token == null || token.getStatus() != Token.Status.VALID)
            throw new IllegalStateException("Token non valido");
        if (choice == null) throw new IllegalArgumentException("Scelta non valida");

        byte[] id = new byte[16];
        random.nextBytes(id);

        byte[] plaintext = encode(choice, id);
        byte[] ciphertext = RSAUtils.encryptOaep(plaintext, aePublicKey);

        KeyPair ephemeral = RSAUtils.generateKeyPair(2048);
        byte[] signedMessage = concat(ciphertext, token.getValue());
        byte[] signature = SignatureUtils.signFdh(signedMessage, ephemeral.getPrivate());

        return new Vote(choice, id, ciphertext, token,
                ephemeral.getPublic(), ephemeral.getPrivate(), signature);
    }

    public static byte[] encode(Vote.Choice choice, byte[] id) {
        if (id.length != 16) throw new IllegalArgumentException("ID deve essere di 128 bit");
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            DataOutputStream data = new DataOutputStream(out);
            data.writeByte(choice.getValue());
            data.write(id);
            data.flush();
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static DecodedVote decode(byte[] plaintext) {
        if (plaintext == null || plaintext.length != 17)
            throw new IllegalArgumentException("Plaintext non valido");
        int value = plaintext[0] & 0xff;
        Vote.Choice choice = Vote.Choice.fromInt(value);
        if (choice == null) throw new IllegalArgumentException("Valore del voto non binario");
        byte[] id = java.util.Arrays.copyOfRange(plaintext, 1, 17);
        return new DecodedVote(choice, id);
    }

    public record DecodedVote(Vote.Choice choice, byte[] id) {
        public DecodedVote {
            id = id.clone();
        }
        @Override public byte[] id() { return id.clone(); }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
