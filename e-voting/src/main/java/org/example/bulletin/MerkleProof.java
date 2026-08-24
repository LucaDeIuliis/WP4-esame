package org.example.bulletin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MerkleProof {
    public record Step(byte[] siblingHash, boolean siblingOnLeft) {
        public Step {
            siblingHash = siblingHash.clone();
        }
        @Override public byte[] siblingHash() { return siblingHash.clone(); }
    }

    private final List<Step> steps;
    private final String rootHex;

    public MerkleProof(List<Step> steps, String rootHex) {
        this.steps = Collections.unmodifiableList(new ArrayList<>(steps));
        this.rootHex = rootHex;
    }

    public List<Step> getSteps() { return steps; }
    public String getRootHex() { return rootHex; }

    public int size() { return steps.size(); }
}
