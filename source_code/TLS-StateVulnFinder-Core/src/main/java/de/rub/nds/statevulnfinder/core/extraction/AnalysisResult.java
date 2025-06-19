/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.List;

public class AnalysisResult {
    private final GraphDetails graphDetails;
    private final List<StateMachineIssue> assumedVulnerabilities;
    private final List<StateMachineIssue> confirmedVulnerabilities;
    private final ExtractorResult extractorResult;
    private final String alphabetName;

    public AnalysisResult(
            GraphDetails graphDetails,
            List<StateMachineIssue> assumedVulnerabilities,
            List<StateMachineIssue> confirmedVulnerabilities,
            ExtractorResult extractorResult,
            String alphabetName) {
        this.graphDetails = graphDetails;
        this.assumedVulnerabilities = assumedVulnerabilities;
        this.confirmedVulnerabilities = confirmedVulnerabilities;
        this.extractorResult = extractorResult;
        this.alphabetName = alphabetName;
    }

    public GraphDetails getGraphDetails() {
        return graphDetails;
    }

    public List<StateMachineIssue> getAssumedVulnerabilities() {
        return assumedVulnerabilities;
    }

    public List<StateMachineIssue> getConfirmedVulnerabilities() {
        return confirmedVulnerabilities;
    }

    public ExtractorResult getExtractorResult() {
        return extractorResult;
    }

    public String getAlphabetName() {
        return alphabetName;
    }
}
