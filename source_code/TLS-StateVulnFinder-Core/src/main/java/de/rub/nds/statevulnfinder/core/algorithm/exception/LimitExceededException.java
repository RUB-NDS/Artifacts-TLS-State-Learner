/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.exception;

/** Used to abort the learning process from within the algorithm */
public class LimitExceededException extends RuntimeException {

    private final LimitationType type;

    public LimitExceededException(LimitationType type) {
        this.type = type;
    }

    public enum LimitationType {
        CONNECTION,
        INITIALIZATION,
        TIME
    }

    public LimitationType getType() {
        return type;
    }

    public boolean stopImmediately() {
        return type == LimitationType.INITIALIZATION || type == LimitationType.TIME;
    }
}
