/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.analysis.transition;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzerProvider;
import java.util.Stack;

public class ClientTransitionAnalyzerProvider extends TransitionAnalyzerProvider {

    @Override
    public TransitionAnalyzer getTransitionAnalyzer(
            Stack<TlsWord> messagesSent, StateMachine stateMachine) {
        return new ClientTransitionAnalyzer(messagesSent, stateMachine);
    }
}
