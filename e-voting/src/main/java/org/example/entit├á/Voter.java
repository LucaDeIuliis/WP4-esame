package org.example.entità;

public class Voter {
    private final String id;
    private final String username;
    private final String password;
    private Token token;
    private Vote vote;

    public Voter(String id, String username, String password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }

    public String getId() { return id; }
    public String getUsername() { return username; }
    public boolean checkPassword(String candidate) { return password.equals(candidate); }
    public Token getToken() { return token; }
    public void setToken(Token token) { this.token = token; }
    public Vote getVote() { return vote; }
    public void setVote(Vote vote) { this.vote = vote; }
}
