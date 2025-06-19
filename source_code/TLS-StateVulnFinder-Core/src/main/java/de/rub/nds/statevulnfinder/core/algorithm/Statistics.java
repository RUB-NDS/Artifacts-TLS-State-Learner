/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

/** Statistics collected over the learning process. */
public class Statistics {
    private final int states;
    private final long learnResets;
    private final long learnInputs;
    private final long allResets;
    private final long allInputs;
    private final long counterexamples;
    private final long duration;
    private final int resets;
    private long connections;
    private final String timing;

    public static class Builder {
        private int states;
        private long counterexamples;
        private long learnResets;
        private long learnInputs;
        private long allResets;
        private long allInputs;
        private long duration;
        private int resets;
        private long connections;
        private String timing;

        public Builder timing(final String timing) {
            this.timing = timing;
            return this;
        }

        public Builder states(final int states) {
            this.states = states;
            return this;
        }

        public Builder counterexamples(final int counterexamples) {
            this.counterexamples = counterexamples;
            return this;
        }

        public Builder learnInputs(final long inputs) {
            this.learnInputs = inputs;
            return this;
        }

        public Builder learnResets(final long resets) {
            this.learnResets = resets;
            return this;
        }

        public Builder allInputs(final long inputs) {
            this.allInputs = inputs;
            return this;
        }

        public Builder allResets(final long resets) {
            this.allResets = resets;
            return this;
        }

        public Builder duration(final long duration) {
            this.duration = duration;
            return this;
        }

        public Builder resets(final int resets) {
            this.resets = resets;
            return this;
        }

        public Builder connections(final int connections) {
            this.connections = connections;
            return this;
        }

        public Statistics build() {
            return new Statistics(
                    states,
                    learnResets,
                    learnInputs,
                    allResets,
                    allInputs,
                    counterexamples,
                    duration,
                    resets,
                    connections,
                    timing);
        }
    }

    private Statistics(
            int states,
            long learnResets,
            long learnInputs,
            long allResets,
            long allInputs,
            long counterexamples,
            long duration,
            int resets,
            long connections,
            String timing) {
        this.states = states;
        this.learnResets = learnResets;
        this.learnInputs = learnInputs;
        this.allResets = allResets;
        this.allInputs = allInputs;
        this.counterexamples = counterexamples;
        this.duration = duration;
        this.resets = resets;
        this.connections = connections;
        this.timing = timing;
    }

    @Override
    public String toString() {
        StringWriter sw = new StringWriter();
        export(sw);
        return sw.toString();
    }

    public void export(Writer writer) {
        PrintWriter out = new PrintWriter(writer);
        out.println("=== STATISTICS ===");
        out.println("Number of states: " + states);
        out.println("Number of counterexamples/hypotheses: " + counterexamples);
        out.println("Number of inputs: " + allInputs);
        out.println("Number of resets: " + allResets);
        out.println("Number of learning inputs: " + learnInputs);
        out.println("Number of learning resets: " + learnResets);
        out.println("Number of resets due to cache inconsistencies: " + resets);
        out.println("Number of connections: " + connections);
        out.println("Time it took to learn model: " + duration + " milliseconds");
        out.println("== TIMING ===");
        out.println(this.timing);
        out.close();
    }

    public void setConnections(long connections) {
        this.connections = connections;
    }

    public int getStates() {
        return states;
    }

    public long getLearnResets() {
        return learnResets;
    }

    public long getLearnInputs() {
        return learnInputs;
    }

    public long getAllResets() {
        return allResets;
    }

    public long getAllInputs() {
        return allInputs;
    }

    public long getCounterexamples() {
        return counterexamples;
    }

    public long getDuration() {
        return duration;
    }

    public int getResets() {
        return resets;
    }

    public long getConnections() {
        return connections;
    }

    public String getTiming() {
        return timing;
    }
}
