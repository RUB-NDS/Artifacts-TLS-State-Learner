/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.constants;

public enum ExtractionStep {
    LEARNING,
    EQUIVALENCE_TEST,
    MAJORITY_VOTE, // we do not count these as individual steps
    REFINING_HYPOTHESIS,
    EXCLUSIVELY_VULNERABILITY_TESTING
}
