/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.analysis.transition;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponseProvider;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextPropertyContainer;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TlsLetterChainProvider;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.server.analysis.response.ServerExpectedResponseProvider;
import java.util.List;

public class ServerTransitionAnalyzer extends TransitionAnalyzer {

    public ServerTransitionAnalyzer(List<TlsWord> messagesSent, StateMachine stateMachine) {
        super(messagesSent, stateMachine);
    }

    @Override
    protected ContextPropertyContainer getContextPropertyContainer(StateMachine stateMachine) {
        return new ServerContextPropertyContainer(stateMachine);
    }

    @Override
    protected TransitionAnalyzer createInstance(
            List<TlsWord> messagesSent, StateMachine stateMachine) {
        return new ServerTransitionAnalyzer(messagesSent, stateMachine);
    }

    @Override
    protected ExpectedResponseProvider getExpectedResponseProvider() {
        return new ServerExpectedResponseProvider();
    }

    @Override
    protected TlsLetterChainProvider getLetterChainProvider() {
        return new ServerTlsLetterChains();
    }
}
