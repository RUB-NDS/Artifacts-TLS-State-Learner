/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

public class StatisticsRecord {

    private final long queriesTotal;
    private final long queriesUncached;
    private final long symbolsQueriedWithHint;
    private final long symbolsQueriedTotal;
    private final long duration;
    private final long states;
    private final long hypotheses;
    private final long cacheExceptions;

    public StatisticsRecord(
            long queriesTotal,
            long queriesUncached,
            long symbolsWithHint,
            long symbolsQueriedTotal,
            long duration,
            long states,
            long hypotheses,
            long cacheExceptions) {
        this.queriesTotal = queriesTotal;
        this.queriesUncached = queriesUncached;
        this.symbolsQueriedWithHint = symbolsWithHint;
        this.symbolsQueriedTotal = symbolsQueriedTotal;
        this.duration = duration;
        this.states = states;
        this.hypotheses = hypotheses;
        this.cacheExceptions = cacheExceptions;
    }

    public StatisticsRecord() {
        this(0, 0, 0, 0, 0, 0, 0, 0);
    }

    /**
     * Constructs a StatisticsRecord representing the difference between two records.
     *
     * @param previous The previous StatisticsRecord to diff against.
     * @param current The current StatisticsRecord.
     */
    public StatisticsRecord(StatisticsRecord previous, StatisticsRecord current) {
        this.queriesTotal = current.queriesTotal - previous.queriesTotal;
        this.queriesUncached = current.queriesUncached - previous.queriesUncached;
        this.symbolsQueriedWithHint =
                current.symbolsQueriedWithHint - previous.symbolsQueriedWithHint;
        this.symbolsQueriedTotal = current.symbolsQueriedTotal - previous.symbolsQueriedTotal;
        this.duration = current.duration - previous.duration;
        this.states = current.states;
        this.hypotheses = current.hypotheses;
        this.cacheExceptions = current.cacheExceptions - previous.cacheExceptions;
    }

    public long getQueriesTotal() {
        return queriesTotal;
    }

    public long getQueriesUncached() {
        return queriesUncached;
    }

    public long getSymbolsQueriedWithHint() {
        return symbolsQueriedWithHint;
    }

    public long getSymbolsQueriedTotal() {
        return symbolsQueriedTotal;
    }

    public long getDuration() {
        return duration;
    }

    public long getStates() {
        return states;
    }

    public long getHypotheses() {
        return hypotheses;
    }

    /**
     * Returns a human-readable string representation of the counters, including ratios for cached
     * queries and symbols queried with hint.
     */
    public String toReadable(boolean includeStateMachineStats) {
        long queriesCached = queriesTotal - queriesUncached;
        double cachedRatio = queriesTotal > 0 ? (queriesCached * 100.0 / queriesTotal) : 0.0;
        double withHintRatio =
                symbolsQueriedTotal > 0
                        ? (symbolsQueriedWithHint * 100.0 / symbolsQueriedTotal)
                        : 0.0;

        long seconds = duration / 1000;
        long ms = duration % 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        seconds = seconds % 60;
        minutes = minutes % 60;

        StringBuilder sb = new StringBuilder();
        sb.append("Statistics:\n");
        sb.append("  Words queried by learner: ")
                .append(queriesTotal)
                .append(" (cached: ")
                .append(queriesCached)
                .append(", uncached: ")
                .append(queriesUncached)
                .append(", cached ratio: ")
                .append(String.format("%.2f", cachedRatio))
                .append("%)\n");
        sb.append("  Symbols sent to SUL: ")
                .append(symbolsQueriedTotal)
                .append(" (with reduced timeout: ")
                .append(symbolsQueriedWithHint)
                .append(", with reduced timeout ratio: ")
                .append(String.format("%.2f", withHintRatio))
                .append("%)\n");
        sb.append("  Duration: ")
                .append(String.format("%dh %dm %ds %dms", hours, minutes, seconds, ms))
                .append("\n");
        sb.append("  Cache conflicts: ").append(cacheExceptions).append("\n");
        if (includeStateMachineStats) {
            sb.append("  States: ").append(states).append("\n");
            sb.append("  Hypotheses: ").append(hypotheses).append("\n");
        }
        return sb.toString();
    }

    /**
     * Returns a human-readable string representation of the counters, including ratios for cached
     * queries and symbols queried with hint.
     */
    public String toReadable() {
        long queriesCached = queriesTotal - queriesUncached;
        double cachedRatio = queriesTotal > 0 ? (queriesCached * 100.0 / queriesTotal) : 0.0;
        double withHintRatio =
                symbolsQueriedTotal > 0
                        ? (symbolsQueriedWithHint * 100.0 / symbolsQueriedTotal)
                        : 0.0;

        long seconds = duration / 1000;
        long ms = duration % 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        seconds = seconds % 60;
        minutes = minutes % 60;

        StringBuilder sb = new StringBuilder();
        sb.append("Statistics:\n");
        sb.append(" Words queried by learner: ")
                .append(queriesTotal)
                .append(" (cached: ")
                .append(queriesCached)
                .append(", uncached: ")
                .append(queriesUncached)
                .append(", cached ratio: ")
                .append(String.format("%.2f", cachedRatio))
                .append("%)\n");
        sb.append("  Symbols sent to SUL: ")
                .append(symbolsQueriedTotal)
                .append(" (with reduced timeout: ")
                .append(symbolsQueriedWithHint)
                .append(", with reduced timeout ratio: ")
                .append(String.format("%.2f", withHintRatio))
                .append("%)\n");
        sb.append("  Duration: ")
                .append(String.format("%dh %dm %ds %dms", hours, minutes, seconds, ms))
                .append("\n");
        sb.append("  States: ").append(states).append("\n");
        sb.append("  Hypotheses: ").append(hypotheses).append("\n");
        sb.append("  Cache conflicts: ").append(cacheExceptions).append("\n");
        return sb.toString();
    }

    @Override
    public String toString() {
        return "StatisticsRecord{"
                + "quereiesTotal="
                + queriesTotal
                + ", queriesUncached="
                + queriesUncached
                + ", symbolsQueriedWithHint="
                + symbolsQueriedWithHint
                + ", symbolsQueriedTotal="
                + symbolsQueriedTotal
                + ", duration="
                + duration
                + ", states="
                + states
                + ", hypotheses="
                + hypotheses
                + ", cacheExceptions="
                + cacheExceptions
                + '}';
    }
}
