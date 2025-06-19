/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.classifier.subclassifier;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.Stack;

public abstract class ResponseSubclassifier {
    public abstract boolean responseIndicatesVulnerability(
            SulResponse sulResponse, boolean onHappyFlow);

    public abstract StateMachineIssue getVulnerability(Stack<TlsWord> wordStack);
}
