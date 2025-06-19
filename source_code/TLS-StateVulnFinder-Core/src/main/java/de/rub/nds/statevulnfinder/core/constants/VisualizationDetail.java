/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.constants;

public enum VisualizationDetail {

    // only log what is necessary and shorten output nodes
    SHORT,
    // try to shorten in- and output
    MEDIUM,
    // do not change anything
    LONG
}
