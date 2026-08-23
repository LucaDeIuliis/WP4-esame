package org.example.protocol;

public class VerificationProtocol {
}

/*
Gestisce sia verifica individuale che universale.

Individuale:

idc
 ↓
trova ciphertext
 ↓
verifica Merkle proof
 ↓
decifra
 ↓
confronta voto + id

Universale:

verifica firma root
 ↓
verifica annuncio chiusura
 ↓
verifica skAE
 ↓
decifra tutte le schede
 ↓
ricalcola risultato
 ↓
confronta con risultato pubblicato
 */