# WP4 – Implementazione e prestazioni

Implementazione simulata del protocollo di e-voting descritto in WP1/WP2/WP3.

## Coerenza con il progetto

- Referendum binario: `YES/NO`.
- Separazione tra Autorità di Registrazione (AR) e Autorità Elettorale (AE).
- Token monouso: `t`, `SHA-256(t)` e firma RSA-FDH dell'AR.
- Cifratura del voto con RSA-OAEP.
- Firma della scheda con chiave RSA effimera del client.
- Bacheca pubblica append-only con Merkle Tree SHA-256.
- Firma della root ad ogni inserimento.
- Ricevuta `idc = SHA-256(c)` firmata dall'AE: miglioramento raccomandato nel WP3.
- Sostituzione del voto prima della chiusura, con firma di revoca.
- Pubblicazione autenticata di `skAE` alla chiusura.
- Scrutinio verificabile e verifica individuale/universale.
- Benchmark delle operazioni crittografiche, Merkle Tree, scrutinio e dimensione dei messaggi.

## Struttura

```text
src/main/java/org/example/
├── autorità/
│   ├── ElectionAutority.java
│   └── RegistrationAutority.java
├── benchmark/
│   └── PerformanceTest.java
├── bulletin/
│   ├── MerkleProof.java
│   ├── MerkleTree.java
│   └── PublicBulletinBoard.java
├── crypto/
│   ├── HashUtils.java
│   ├── KeyManager.java
│   ├── RSAUtils.java
│   └── SignatureUtils.java
├── entità/
│   ├── Token.java
│   ├── Vote.java
│   ├── VoteRecord.java
│   └── Voter.java
├── protocol/
│   ├── RegistrationProtocol.java
│   ├── RevocationProtocol.java
│   ├── TallyProtocol.java
│   ├── VerificationProtocol.java
│   └── VotingProtocol.java
└── Main.java
```

## Requisiti

- Java 17+
- Maven è previsto dal `pom.xml`, ma il progetto non richiede librerie crittografiche esterne: usa le API Java standard.

## Esecuzione

Da `e-voting/`:

```bash
javac -encoding UTF-8 -d target/classes $(find src/main/java -name "*.java")
java -cp target/classes org.example.Main
```

Il programma esegue una simulazione completa e stampa:

- numero di schede pubblicate;
- risultato YES/NO;
- root Merkle finale;
- verifica universale;
- verifica individuale;
- verifica della ricevuta firmata dall'AE.

## Benchmark

Per evitare di avviare accidentalmente esperimenti molto lunghi, le dimensioni vengono passate da riga di comando:

```bash
java -cp target/classes org.example.Main benchmark 10
java -cp target/classes org.example.Main benchmark 10 100
java -cp target/classes org.example.Main benchmark 10 100 1000
```

L'output è CSV e comprende:

- generazione chiavi RSA;
- RSA-OAEP encryption;
- RSA-FDH signing;
- RSA-FDH verification;
- inserimento/protocollo + Merkle;
- verifica Merkle;
- scrutinio;
- tempo totale;
- dimensione del messaggio.

La generazione della chiave RSA effimera per ogni voto è intenzionalmente mantenuta nel benchmark perché è prevista dal protocollo WP2; per questo gli esperimenti con migliaia di elettori possono essere costosi.

## Nota implementativa

La simulazione non realizza una rete reale, TLS o una CA: questi elementi sono modellati come separazione logica e uso delle primitive crittografiche nel processo locale. Il WP4 è quindi un ambiente stand-alone, coerente con la traccia, che permette di verificare il flusso e misurare i costi delle operazioni.
