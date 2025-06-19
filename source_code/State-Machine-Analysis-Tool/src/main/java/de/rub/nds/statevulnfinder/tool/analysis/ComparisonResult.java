/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

public class ComparisonResult {

    private String identifier;

    private boolean isLowConfidence = true;

    public boolean isLowConfidence() {
        return isLowConfidence;
    }

    public void setLowConfidence(boolean isLowConfidence) {
        this.isLowConfidence = isLowConfidence;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    private int stateNamesCompared;

    public int getStateNamesCompared() {
        return stateNamesCompared;
    }

    private int stateNamesMatching;

    public int getStateNamesMatching() {
        return stateNamesMatching;
    }

    private int sharedAlphabetSize;

    public int getSharedAlphabetSize() {
        return sharedAlphabetSize;
    }

    public void setSharedAlphabetSize(int sharedAlphabetSize) {
        this.sharedAlphabetSize = sharedAlphabetSize;
    }

    private long edgesTested;

    public long getEdgesTested() {
        return edgesTested;
    }

    private long edgesMatched;

    public long getEdgesMatched() {
        return edgesMatched;
    }

    private double similarity = -1;

    public double getSimilarity() {
        return similarity;
    }

    public void setSimilarity(double similarity) {
        this.similarity = similarity;
    }

    public void edgeMatched() {
        edgesTested++;
        edgesMatched++;
    }

    public void edgeDiffers() {
        edgesTested++;
    }

    public void updateStateNameComparison(int statesOverall, int statesMatching) {
        this.stateNamesCompared += statesOverall;
        this.stateNamesMatching += statesMatching;
    }
}
