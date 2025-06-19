/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.scanner.core.report.ScanReport;
import java.util.LinkedList;
import java.util.List;

public class LearnerReport {
    private final List<AnalysisResult> analysisResults;
    private ScanReport scanReport;
    private boolean incomplete;
    private long totalExecutionTime;
    private long totalCacheExceptions;
    private long totalConnections;
    private int timeout;

    public LearnerReport() {
        analysisResults = new LinkedList<>();
    }

    public LearnerReport(ScanReport scanReport) {
        this();
        this.scanReport = scanReport;
    }

    public void addResult(AnalysisResult result) {
        analysisResults.add(result);
        if (result.getExtractorResult().isAbortedLearning()) {
            incomplete = true;
        }
        totalExecutionTime += result.getExtractorResult().getStatistics().getDuration();
    }

    public List<AnalysisResult> getAnalysisResults() {
        return analysisResults;
    }

    public boolean isIncomplete() {
        return incomplete;
    }

    public long getTotalExecutionTime() {
        return totalExecutionTime;
    }

    public long getTotalCacheExceptions() {
        return totalCacheExceptions;
    }

    public long getTotalConnections() {
        return totalConnections;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public ScanReport getScanReport() {
        return scanReport;
    }

    public void setScanReport(ScanReport scanReport) {
        this.scanReport = scanReport;
    }
}
