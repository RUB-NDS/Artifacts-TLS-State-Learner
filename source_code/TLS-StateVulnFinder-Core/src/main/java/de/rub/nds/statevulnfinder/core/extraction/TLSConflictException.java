/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import net.automatalib.incremental.ConflictException;
import net.automatalib.words.Word;

/**
 * Extends {@link ConflictException} by storing the input and conflicting outputs of the conflict.
 */
public class TLSConflictException extends ConflictException {

    // the sequence of TLS messages that lead to the conflictException
    Word<TlsWord> input;

    // the old previously gathered information
    Word<SulResponse> expectedOutput;

    // the new conflicting information
    Word<SulResponse> newOutput;

    public TLSConflictException(
            Word<TlsWord> input, Word<SulResponse> expectedOutput, Word<SulResponse> newOutput) {
        this.input = input;
        this.expectedOutput = expectedOutput;
        this.newOutput = newOutput;
    }

    public Word<TlsWord> getInput() {
        return input;
    }

    public Word<SulResponse> getExpectedOutput() {
        return expectedOutput;
    }

    public Word<SulResponse> getNewOutput() {
        return newOutput;
    }
}
