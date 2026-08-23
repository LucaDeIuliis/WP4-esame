package org.example.protocol;

public class RevocationProtocol {
}

/*
Per la funzionalità sostituzione del voto.

nuova autenticazione
 ↓
nuovo token t'
 ↓
invalidazione t
 ↓
nuovo voto
 ↓
firma di revoca σinv
 ↓
AE marca il vecchio voto come sostituito
 */