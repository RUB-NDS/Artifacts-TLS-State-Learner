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

/**
 * Bundles inputs that may form arbitrary chains following the entryType e.g Fin - APP - HEARTBEAT -
 * APP
 */
public class PoolLetterChain extends LetterChain {

    private final Set<TlsWordType> pooledInputs;
    private final TlsWordType entryType;
    private final ContextProperty[] requiredContextProperties;
    private boolean required = true;

    public PoolLetterChain(
            TlsWordType entryType, ContextProperty sharedProperty, TlsWordType... pooledTypes) {
        this.entryType = entryType;
        this.pooledInputs = new HashSet<TlsWordType>(Arrays.asList(pooledTypes));
        this.requiredContextProperties = new ContextProperty[] {sharedProperty};
    }

    public PoolLetterChain(TlsWordType entryType, TlsWordType... pooledTypes) {
        this.entryType = entryType;
        this.pooledInputs = new HashSet<TlsWordType>(Arrays.asList(pooledTypes));
        this.requiredContextProperties = new ContextProperty[0];
    }

    @Override
    public boolean appliesTo(
            TlsWordType givenPredecessor,
            TlsWordType givenSuccessor,
            ContextPropertyContainer propertyContainer) {
        return propertyContainer.doPropertiesApply(requiredContextProperties)
                && ((TlsWordType.effectivelyEquals(givenPredecessor, entryType)
                                && typeMatchesPooled(givenSuccessor))
                        || typeMatchesPooled(givenPredecessor)
                                && typeMatchesPooled(givenSuccessor));
    }

    private boolean typeMatchesPooled(TlsWordType type) {
        return pooledInputs.stream()
                .anyMatch(pooledType -> TlsWordType.effectivelyEquals(type, pooledType));
    }

    @Override
    public boolean isRequired() {
        return required;
    }

    @Override
    public ContextProperty[] getContextConditions() {
        return requiredContextProperties;
    }

    @Override
    public void setRequired(boolean required) {
        this.required = required;
    }

    @Override
    public Set<TlsWordType> getAllDefinedSuccessors() {
        return pooledInputs;
    }
}
