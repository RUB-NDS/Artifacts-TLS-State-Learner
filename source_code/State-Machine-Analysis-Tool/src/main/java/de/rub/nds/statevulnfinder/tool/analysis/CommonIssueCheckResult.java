/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.List;
import java.util.Set;

public class CommonIssueCheckResult {
    private final List<StateMachineIssue> unfilteredIssues;

    public List<StateMachineIssue> getUnfilteredIssues() {
        return unfilteredIssues;
    }

    private final Set<CommonIssue> commonIssuesFound;

    public Set<CommonIssue> getCommonIssuesFound() {
        return commonIssuesFound;
    }

    public CommonIssueCheckResult(
            List<StateMachineIssue> unfilteredIssues, Set<CommonIssue> commonIssuesFound) {
        this.unfilteredIssues = unfilteredIssues;
        this.commonIssuesFound = commonIssuesFound;
    }

    public boolean onlyCommon() {
        return unfilteredIssues.isEmpty();
    }
}
