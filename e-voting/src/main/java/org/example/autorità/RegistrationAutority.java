package org.example.autorità;

public class RegistrationAutority {
}

/*
autenticare elettore
↓
controllare diritto al voto
↓
controllare che non abbia già ricevuto token
↓
generare t
↓
calcolare SHA-256(t)
↓
firmare hash del token
↓
comunicare hash + firma all'AE
↓
consegnare t all'elettore
 */