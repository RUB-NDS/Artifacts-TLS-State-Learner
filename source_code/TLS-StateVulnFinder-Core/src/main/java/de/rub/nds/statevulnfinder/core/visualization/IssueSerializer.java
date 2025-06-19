/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.visualization;

import de.rub.nds.statevulnfinder.core.constants.StateMachineIssueType;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.*;

public class IssueSerializer {

    private List<StateMachineIssue> issueList;

    private Map<StateMachineIssueType, Set<String>> issueMap;

    public IssueSerializer() {
        this.issueList = new LinkedList<>();
    }

    public IssueSerializer(Collection<StateMachineIssue> issues) {
        this.issueList = new LinkedList<>(issues);
    }

    public List<StateMachineIssue> getIssueList() {
        return issueList;
    }

    public void setVulnerabilityList(Collection<StateMachineIssue> vulnerabilities) {
        this.issueList = new LinkedList<>(vulnerabilities);
    }

    private void sort() {
        issueMap = new HashMap<>();
        // prepare hashMap
        for (StateMachineIssueType type : StateMachineIssueType.values()) {
            issueMap.put(type, new HashSet<>());
        }
        // add each issue String to their respective issue type
        for (StateMachineIssue issue : issueList) {
            issueMap.get(issue.getType()).add(issue.toString());
        }
    }

    /**
     * Serializes all issues into the given file
     *
     * @param file File to serialize into
     * @throws IOException When the file cannot be written to
     */
    public void serialize(File file) throws IOException {
        this.serialize(new FileWriter(file));
    }

    public void serialize(Writer writer) throws IOException {
        // sort issues in a map
        StringBuilder preStats = new StringBuilder();
        preStats.append("#Summary\n\n");
        StringBuilder mainStats = new StringBuilder();
        mainStats.append("#Issues\n\n");
        this.sort();
        for (StateMachineIssueType issueType : issueMap.keySet()) {
            Set<String> descriptions = issueMap.get(issueType);
            // how often did we encounter this issue
            preStats.append("- ")
                    .append(issueType)
                    .append(": ")
                    .append(issueMap.get(issueType).size())
                    .append(" occurences\n");
            if (!descriptions.isEmpty()) {
                // add detailed descriptions for each vulnerability grouped by type
                mainStats.append("##Issues of type ").append(issueType).append("\n");
                int counter = 1;
                for (String description : descriptions) {
                    mainStats.append(counter).append(". ").append(description).append("\n");
                    counter++;
                }
                mainStats.append("\n");
            }
        }
        preStats.append("\n");
        writer.write(preStats.toString());
        writer.write(mainStats.toString());
        writer.close();
    }
}
