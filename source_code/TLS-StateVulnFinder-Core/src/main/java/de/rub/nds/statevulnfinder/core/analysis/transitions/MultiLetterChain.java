/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.transitions;

import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Bundles inputs that may follow a given previous input (eg A - B, A - C, and A - D). */
public class MultiLetterChain extends LetterChain {

    private final TlsWordType previousInput;
    private final Set<TlsWordType> nextInputs;
    private final ContextProperty[] contextConditions;
    private boolean required = true;

    public MultiLetterChain(
            TlsWordType previousInput,
            ContextProperty contextCondition,
            TlsWordType... nextInputs) {
        this.previousInput = previousInput;
        this.nextInputs = new HashSet<>(Arrays.asList(nextInputs));
        this.contextConditions = new ContextProperty[] {contextCondition};
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
    public boolean appliesTo(
            TlsWordType givenPredecessor,
            TlsWordType givenSuccessor,
            ContextPropertyContainer propertyContainer) {
        return propertyContainer.doPropertiesApply(contextConditions)
                && TlsWordType.effectivelyEquals(givenPredecessor, previousInput)
                && nextInputs.stream()
                        .anyMatch(
                                listedNext ->
                                        TlsWordType.effectivelyEquals(givenSuccessor, listedNext));
    }

    @Override
    public ContextProperty[] getContextConditions() {
        return contextConditions;
    }

    @Override
    public Set<TlsWordType> getAllDefinedSuccessors() {
        return nextInputs;
    }
}
