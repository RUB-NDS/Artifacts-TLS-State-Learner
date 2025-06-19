/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.transitions;

import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Defines a permitted chain of exactly one input and one following input */
public class SimpleLetterChain extends LetterChain {
    private final TlsWordType previousInput;
    private final TlsWordType nextInput;
    private final ContextProperty[] contextConditions;
    private boolean required = true;

    public SimpleLetterChain(TlsWordType previousInput, TlsWordType nextInput) {
        this.previousInput = previousInput;
        this.nextInput = nextInput;
        this.contextConditions = new ContextProperty[0];
    }

    public SimpleLetterChain(
            TlsWordType previousInput,
            TlsWordType nextInput,
            ContextProperty... contextConditions) {
        this.previousInput = previousInput;
        this.nextInput = nextInput;
        this.contextConditions = contextConditions;
    }

    public SimpleLetterChain(
            boolean required,
            TlsWordType previousInput,
            TlsWordType nextInput,
            ContextProperty... contextConditions) {
        this.required = required;
        this.previousInput = previousInput;
        this.nextInput = nextInput;
        this.contextConditions = contextConditions;
    }

    public TlsWordType getPreviousInput() {
        return previousInput;
    }

    public TlsWordType getNextInput() {
        return nextInput;
    }

    @Override
    public ContextProperty[] getContextConditions() {
        return contextConditions;
    }

    @Override
    public boolean appliesTo(
            TlsWordType givenPredecessor,
            TlsWordType givenSuccessor,
            ContextPropertyContainer propertyContainer) {
        return TlsWordType.effectivelyEquals(givenPredecessor, previousInput)
                && TlsWordType.effectivelyEquals(givenSuccessor, nextInput)
                && propertyContainer.doPropertiesApply(contextConditions);
    }

    @Override
    public boolean isRequired() {
        return required;
    }

    @Override
    public void setRequired(boolean required) {
        this.required = required;
    }

    @Override
    public Set<TlsWordType> getAllDefinedSuccessors() {
        return new HashSet<>(Arrays.asList(nextInput));
    }
}
