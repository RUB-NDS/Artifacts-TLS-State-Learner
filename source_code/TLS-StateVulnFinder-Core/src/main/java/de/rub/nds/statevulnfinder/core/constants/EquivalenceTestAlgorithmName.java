/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.constants;

public enum EquivalenceTestAlgorithmName {
    HAPPY_FLOW,
    W_METHOD,
    MODIFIED_W_METHOD,
    WP_METHOD,
    RANDOM_WORDS,
    RANDOM_WALK,
    RANDOM_WP_METHOD,
    RANDOM_WORDS_STATE,
    VULNERABILITY
}
