/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ExtractorResult {

    private StateMachine learnedModel;
    private StatisticsRecord statistics;
    private final List<StateMachine> hypotheses;
    private boolean abortedLearning = false;
    private boolean probablyBlacklisted = false;

    public ExtractorResult() {
        this.hypotheses = new ArrayList<>();
    }

    public StateMachine getLearnedModel() {
        return learnedModel;
    }

    void setLearnedModel(StateMachine learnedModel) {
        this.learnedModel = learnedModel;
    }

    public StatisticsRecord getStatistics() {
        return statistics;
    }

    void setStatistics(StatisticsRecord statistics) {
        this.statistics = statistics;
    }

    void addHypothesis(StateMachine hypothesis) {
        hypotheses.add(hypothesis);
    }

    public List<StateMachine> getHypotheses() {
        return Collections.unmodifiableList(hypotheses);
    }

    public StateMachine getLastHypothesis() {
        if (hypotheses != null && !hypotheses.isEmpty()) {
            return hypotheses.get(hypotheses.size() - 1);
        }
        return null;
    }

    public void filterBrokenHypotheses() {
        if (hypotheses != null) {
            for (int i = 0; i < hypotheses.size(); i++) {
                if (isBrokenHypothesis(hypotheses.get(i))) {
                    hypotheses.remove(i);
                    i--;
                }
            }
        }
    }

    /**
     * When aborting learning due to reaching one of our limits, hypotheses may contain invalid
     * edges where the successor is set to null causing various NPEs. This method eliminates such
     * hypotheses.
     *
     * @param hypothesis Hypothesis in question
     * @return true if incomplete, false if complete
     */
    private boolean isBrokenHypothesis(StateMachine hypothesis) {
        for (Object state : hypothesis.getMealyMachine().getStates()) {
            for (TlsWord input : hypothesis.getAlphabet()) {
                if (hypothesis.getMealyMachine().getSuccessor(state, input) == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public void clearHypotheses() {
        hypotheses.clear();
    }

    public boolean isAbortedLearning() {
        return abortedLearning;
    }

    public void setIncomplete(boolean incomplete) {
        this.abortedLearning = incomplete;
    }

    public void reset() {
        learnedModel = null;
        hypotheses.clear();
        statistics = null;
        abortedLearning = false;
    }

    public boolean isProbablyBlacklisted() {
        return probablyBlacklisted;
    }

    public void setProbablyBlacklisted(boolean probablyBlacklisted) {
        this.probablyBlacklisted = probablyBlacklisted;
    }
}
