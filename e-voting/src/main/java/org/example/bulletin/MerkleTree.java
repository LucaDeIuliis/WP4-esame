package org.example.bulletin;

import org.example.crypto.HashUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class MerkleTree {
    private final List<byte[]> leaves = new ArrayList<>();

    public synchronized void addLeaf(byte[] data) {
        leaves.add(HashUtils.sha256(data));
    }

    public synchronized int size() { return leaves.size(); }

    public synchronized byte[] getRoot() {
        if (leaves.isEmpty()) return HashUtils.sha256("EMPTY");
        List<byte[]> level = copyLevel(leaves);
        while (level.size() > 1) level = parentLevel(level);
        return level.get(0).clone();
    }

    public synchronized MerkleProof proofFor(byte[] data) {
        byte[] target = HashUtils.sha256(data);
        int index = indexOfLeaf(target);
        if (index < 0) throw new IllegalArgumentException("Foglia non presente nel Merkle Tree");

        List<MerkleProof.Step> steps = new ArrayList<>();
        List<byte[]> level = copyLevel(leaves);
        int current = index;

        while (level.size() > 1) {
            int sibling = (current % 2 == 0) ? Math.min(current + 1, level.size() - 1) : current - 1;
            boolean siblingOnLeft = sibling < current;
            steps.add(new MerkleProof.Step(level.get(sibling), siblingOnLeft));
            level = parentLevel(level);
            current /= 2;
        }
        return new MerkleProof(steps, HashUtils.hex(level.get(0)));
    }

    public static boolean verify(byte[] data, MerkleProof proof, byte[] expectedRoot) {
        byte[] current = HashUtils.sha256(data);
        for (MerkleProof.Step step : proof.getSteps()) {
            current = step.siblingOnLeft()
                    ? hashPair(step.siblingHash(), current)
                    : hashPair(current, step.siblingHash());
        }
        return Arrays.equals(current, expectedRoot)
                && HashUtils.hex(current).equals(proof.getRootHex());
    }

    private int indexOfLeaf(byte[] target) {
        for (int i = 0; i < leaves.size(); i++)
            if (Arrays.equals(leaves.get(i), target)) return i;
        return -1;
    }

    private static List<byte[]> copyLevel(List<byte[]> level) {
        List<byte[]> result = new ArrayList<>(level.size());
        for (byte[] h : level) result.add(h.clone());
        return result;
    }

    private static List<byte[]> parentLevel(List<byte[]> level) {
        List<byte[]> parents = new ArrayList<>((level.size() + 1) / 2);
        for (int i = 0; i < level.size(); i += 2) {
            byte[] left = level.get(i);
            byte[] right = (i + 1 < level.size()) ? level.get(i + 1) : left;
            parents.add(hashPair(left, right));
        }
        return parents;
    }

    private static byte[] hashPair(byte[] left, byte[] right) {
        byte[] joined = new byte[left.length + right.length];
        System.arraycopy(left, 0, joined, 0, left.length);
        System.arraycopy(right, 0, joined, left.length, right.length);
        return HashUtils.sha256(joined);
    }
}
