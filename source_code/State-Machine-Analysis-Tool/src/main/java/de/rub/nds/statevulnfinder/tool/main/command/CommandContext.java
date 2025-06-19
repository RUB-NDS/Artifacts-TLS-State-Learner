/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.FastMealySULCache;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.statevulnfinder.server.ServerVulnerabilityFinder;
import de.rub.nds.statevulnfinder.server.config.ServerVulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.server.sul.TlsServerSul;
import java.util.LinkedList;
import java.util.List;

/** Context object that holds shared state between commands. */
public class CommandContext {

    private StateMachine stateMachine;
    private GraphDetails graphDetails;
    private ServerVulnerabilityFinder vulnerabilityFinder;
    private ServerVulnerabilityFinderConfig config;
    private ScanReport scanReport;
    private TlsServerSul tlsServerSul;
    private FastMealySULCache sulCache;
    private String writtenScanReport = "";
    private List<StateMachineIssue> foundVulnerabilities;
    private List<List<TlsWord>> recentMessageSequences = new LinkedList<>();
    private String xmlFilePath = null;
    private boolean silentMode = false;

    public StateMachine getStateMachine() {
        return stateMachine;
    }

    public void setStateMachine(StateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    public GraphDetails getGraphDetails() {
        return graphDetails;
    }

    public void setGraphDetails(GraphDetails graphDetails) {
        this.graphDetails = graphDetails;
    }

    public ServerVulnerabilityFinder getVulnerabilityFinder() {
        return vulnerabilityFinder;
    }

    public void setVulnerabilityFinder(ServerVulnerabilityFinder vulnerabilityFinder) {
        this.vulnerabilityFinder = vulnerabilityFinder;
    }

    public ServerVulnerabilityFinderConfig getConfig() {
        return config;
    }

    public void setConfig(ServerVulnerabilityFinderConfig config) {
        this.config = config;
    }

    public ScanReport getScanReport() {
        return scanReport;
    }

    public void setScanReport(ScanReport scanReport) {
        this.scanReport = scanReport;
    }

    public TlsServerSul getTlsServerSul() {
        return tlsServerSul;
    }

    public void setTlsServerSul(TlsServerSul tlsServerSul) {
        this.tlsServerSul = tlsServerSul;
    }

    public FastMealySULCache getSulCache() {
        return sulCache;
    }

    public void setSulCache(FastMealySULCache sulCache) {
        this.sulCache = sulCache;
    }

    public String getWrittenScanReport() {
        return writtenScanReport;
    }

    public void setWrittenScanReport(String writtenScanReport) {
        this.writtenScanReport = writtenScanReport;
    }

    public List<StateMachineIssue> getFoundVulnerabilities() {
        return foundVulnerabilities;
    }

    public void setFoundVulnerabilities(List<StateMachineIssue> foundVulnerabilities) {
        this.foundVulnerabilities = foundVulnerabilities;
    }

    public List<List<TlsWord>> getRecentMessageSequences() {
        return recentMessageSequences;
    }

    public void setRecentMessageSequences(List<List<TlsWord>> recentMessageSequences) {
        this.recentMessageSequences = recentMessageSequences;
    }

    public String getXmlFilePath() {
        return xmlFilePath;
    }

    public void setXmlFilePath(String xmlFilePath) {
        this.xmlFilePath = xmlFilePath;
    }

    public boolean isStateMachineLoaded() {
        return stateMachine != null;
    }

    public boolean isGraphDetailsAnalyzed() {
        return graphDetails != null;
    }

    public boolean isSilentMode() {
        return silentMode;
    }

    public void setSilentMode(boolean silentMode) {
        this.silentMode = silentMode;
    }
}
