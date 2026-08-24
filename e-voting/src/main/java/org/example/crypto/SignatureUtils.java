package org.example.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public final class SignatureUtils {
    private SignatureUtils() {}

    /**
     * RSA-FDH: sigma = H(m)^d mod N, con H = SHA-256.
     * L'algoritmo non applica SHA-256 una seconda volta sul digest fornito dal chiamante.
     */
    public static byte[] signFdh(byte[] message, PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateKey rsa)) {
            throw new IllegalArgumentException("La chiave deve essere RSA");
        }
        byte[] digest = HashUtils.sha256(message);
        BigInteger s = new BigInteger(1, digest).modPow(rsa.getPrivateExponent(), rsa.getModulus());
        return toFixedLength(s, modulusLength(rsa.getModulus()));
    }

    public static boolean verifyFdh(byte[] message, byte[] signature, PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey rsa) || signature == null) return false;
        int len = modulusLength(rsa.getModulus());
        if (signature.length != len) return false;
        BigInteger s = new BigInteger(1, signature);
        if (s.compareTo(rsa.getModulus()) >= 0) return false;
        BigInteger recovered = s.modPow(rsa.getPublicExponent(), rsa.getModulus());
        BigInteger expected = new BigInteger(1, HashUtils.sha256(message));
        return recovered.equals(expected);
    }

    private static int modulusLength(BigInteger n) {
        return (n.bitLength() + 7) / 8;
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return out;
    }
}
