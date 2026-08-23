package org.example.protocol;

public class VotingProtocol {
}

/*
Simula:

Voter
 ↓
genera v
 ↓
genera id
 ↓
m = v || id
 ↓
RSA-OAEP
 ↓
firma RSA-FDH
 ↓
(c,t,pkₑ,σv)
 ↓
AE
 */