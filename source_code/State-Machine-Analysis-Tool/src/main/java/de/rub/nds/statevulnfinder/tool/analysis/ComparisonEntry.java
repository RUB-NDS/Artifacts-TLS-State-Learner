/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;

public class ComparisonEntry {
    private final StateMachine stateMachine;
    private final GraphDetails graphDetails;
    private final String name;

    public ComparisonEntry(StateMachine stateMachine, GraphDetails graphDetails, String name) {
        this.stateMachine = stateMachine;
        this.graphDetails = graphDetails;
        this.name = name;
    }

    public StateMachine getStateMachine() {
        return stateMachine;
    }

    public GraphDetails getGraphDetails() {
        return graphDetails;
    }

    public String getName() {
        return name;
    }
}
