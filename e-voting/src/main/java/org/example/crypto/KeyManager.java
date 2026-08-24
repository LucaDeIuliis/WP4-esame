package org.example.crypto;

import java.security.KeyPair;

public class KeyManager {
    private final int rsaBits;
    private final KeyPair aeKeys;
    private final KeyPair arKeys;
    private final KeyPair aeCertificateKeys;

    public KeyManager() {
        this(2048);
    }

    public KeyManager(int rsaBits) {
        if (rsaBits < 2048) throw new IllegalArgumentException("RSA deve essere >= 2048 bit");
        this.rsaBits = rsaBits;
        this.aeKeys = RSAUtils.generateKeyPair(rsaBits);
        this.arKeys = RSAUtils.generateKeyPair(rsaBits);
        this.aeCertificateKeys = RSAUtils.generateKeyPair(rsaBits);
    }

    public int getRsaBits() { return rsaBits; }
    public KeyPair getAeKeys() { return aeKeys; }
    public KeyPair getArKeys() { return arKeys; }
    public KeyPair getAeCertificateKeys() { return aeCertificateKeys; }
}
