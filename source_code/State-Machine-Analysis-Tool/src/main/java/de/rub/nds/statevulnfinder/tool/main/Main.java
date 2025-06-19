/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main;

/** Legacy main class for backwards compatibility. Delegates to the new StateMachineAnalysisTool. */
public class Main {

    public static void main(String[] args) {
        // Delegate to the new tool
        StateMachineAnalysisTool.main(args);
    }
}
