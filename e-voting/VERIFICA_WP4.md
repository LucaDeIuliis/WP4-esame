# Verifica generale WP4

Data verifica: 2026-08-25

## Build

- Target Java dichiarato nel `pom.xml`: Java 17.
- Compilazione verificata con `javac --release 17` e UTF-8.
- Tutte le sorgenti `src/main/java` compilano senza errori.
- Maven non era installato nell'ambiente di verifica; per questo il build è stato verificato direttamente con `javac`. Il `pom.xml` resta valido per un ambiente con Maven.

## Esecuzione principale

`java -cp target/classes org.example.Main`

Esito verificato:

- Schede pubblicate: 4
- Risultato: YES=1, NO=2
- Verifica universale: `true`
- Verifica individuale Alice: `true`
- Verifica individuale Bob: `true`
- Ricevuta firmata AE: `true`

## Benchmark

`java -cp target/classes org.example.Main benchmark 5`

Esito verificato con output CSV contenente:

- generazione chiavi RSA;
- RSA-OAEP encryption;
- RSA-FDH signing;
- RSA-FDH verification;
- protocollo + Merkle Tree;
- verifica Merkle;
- tally;
- tempo totale;
- dimensione del messaggio.

## Controlli funzionali aggiuntivi

Sono stati verificati separatamente:

- accettazione di un voto valido;
- rifiuto del replay dello stesso token/voto;
- validazione di una Merkle proof corretta;
- rifiuto di una Merkle proof con dato alterato;
- chiusura e scrutinio;
- verifica universale;
- verifica individuale post-chiusura;
- verifica della ricevuta firmata dall'AE.
- rifiuto della verifica individuale del voto precedente dopo una sostituzione;
- verifica del voto sostitutivo;
- verifica della firma della ricevuta del voto sostitutivo.
## Nomi e struttura

I nomi delle classi e dei package sono stati mantenuti coerenti con gli scheletri originali del repository. In particolare, `ElectionAutority` e `RegistrationAutority` sono nomi
già presenti nello scheletro iniziale e sono stati mantenuti per non
rompere la coerenza con gli altri WP. I package Java effettivamente
utilizzati sono `autorita` ed `entita`.

## Nota

Il progetto è uno stand-alone simulato: non implementa una rete reale, TLS/CA reali o un'infrastruttura distribuita. Questa scelta è intenzionale e coerente con l'impostazione WP4 del progetto.
