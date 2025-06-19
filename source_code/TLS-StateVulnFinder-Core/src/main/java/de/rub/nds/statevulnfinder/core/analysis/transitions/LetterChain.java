/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.transitions;

import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import java.util.Set;

public abstract class LetterChain {
    public abstract boolean isRequired();

    public abstract void setRequired(boolean required);

    public abstract boolean appliesTo(
            TlsWordType givenPredecessor,
            TlsWordType givenSuccessor,
            ContextPropertyContainer propertyContainer);

    public abstract ContextProperty[] getContextConditions();

    public abstract Set<TlsWordType> getAllDefinedSuccessors();
}
