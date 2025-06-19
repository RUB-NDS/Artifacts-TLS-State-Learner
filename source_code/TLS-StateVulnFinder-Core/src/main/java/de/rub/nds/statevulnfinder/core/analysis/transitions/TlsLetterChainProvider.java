/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.transitions;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public abstract class TlsLetterChainProvider {

    public LetterChain[] getAllowedTLS12LetterChains() {
        return ArrayConverter.concatenate(
                getRequiredTLS12LetterChains(), getOptionalTLS12LetterChains());
    }

    public LetterChain[] getAllowedTLS13LetterChains() {
        return ArrayConverter.concatenate(
                getRequiredTLS13LetterChains(), getOptionalTLS13LetterChains());
    }

    public LetterChain[] getAllAllowedTLSLetterChains() {
        LetterChain[] allTls12Allowed = getAllowedTLS12LetterChains();
        LetterChain[] allTls13Allowed = getAllowedTLS13LetterChains();
        LetterChain[] combinedLetterChains =
                new LetterChain[allTls12Allowed.length + allTls13Allowed.length];
        System.arraycopy(allTls12Allowed, 0, combinedLetterChains, 0, allTls12Allowed.length);
        System.arraycopy(
                allTls13Allowed,
                0,
                combinedLetterChains,
                allTls12Allowed.length,
                allTls13Allowed.length);
        return combinedLetterChains;
    }

    public abstract LetterChain[] getRequiredTLS12LetterChains();

    public abstract LetterChain[] getRequiredTLS13LetterChains();

    public abstract LetterChain[] getOptionalTLS13LetterChains();

    public abstract LetterChain[] getOptionalTLS12LetterChains();
}
