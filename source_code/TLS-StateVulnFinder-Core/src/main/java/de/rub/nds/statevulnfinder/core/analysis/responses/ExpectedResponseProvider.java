/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.responses;

public abstract class ExpectedResponseProvider {
    public abstract ExpectedResponse[] getExpectedTls12Responses();

    public abstract ExpectedResponse[] getExpectedTls13Responses();

    public ExpectedResponse[] getAllExpectedResponses() {
        ExpectedResponse[] combinedExpectedResponses =
                new ExpectedResponse
                        [getExpectedTls12Responses().length + getExpectedTls13Responses().length];
        System.arraycopy(
                getExpectedTls12Responses(),
                0,
                combinedExpectedResponses,
                0,
                getExpectedTls12Responses().length);
        System.arraycopy(
                getExpectedTls13Responses(),
                0,
                combinedExpectedResponses,
                getExpectedTls12Responses().length,
                getExpectedTls13Responses().length);
        return combinedExpectedResponses;
    }
}
