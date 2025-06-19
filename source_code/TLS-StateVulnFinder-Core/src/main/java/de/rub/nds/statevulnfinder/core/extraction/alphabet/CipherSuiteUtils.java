/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CipherSuiteUtils {

    // choosing from a set causes unwanted randomness
    // it causes that the results of the TLS-StateVulnFinder are not reproducible and can not be
    // compared.
    public static List<CipherSuite> getSortedCipherSuites(Set<CipherSuite> cipherSuites) {
        return cipherSuites.stream().sorted().collect(Collectors.toList());
    }
}
