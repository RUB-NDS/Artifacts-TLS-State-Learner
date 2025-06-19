/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.analysis.transition;

import de.rub.nds.statevulnfinder.client.analysis.response.ClientExpectedResponseProvider;
import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponseProvider;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextPropertyContainer;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TlsLetterChainProvider;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import java.util.List;

public class ClientTransitionAnalyzer extends TransitionAnalyzer {

    public ClientTransitionAnalyzer(List<TlsWord> messagesSent, StateMachine stateMachine) {
        super(messagesSent, stateMachine);
    }

    @Override
    protected TransitionAnalyzer createInstance(
            List<TlsWord> messagesSent, StateMachine stateMachine) {
        return new ClientTransitionAnalyzer(messagesSent, stateMachine);
    }

    @Override
    protected ContextPropertyContainer getContextPropertyContainer(StateMachine stateMachine) {
        return new ClientContextPropertyContainer(stateMachine);
    }

    @Override
    protected ExpectedResponseProvider getExpectedResponseProvider() {
        return new ClientExpectedResponseProvider();
    }

    @Override
    protected TlsLetterChainProvider getLetterChainProvider() {
        return new ClientTlsLetterChains();
    }

    @Override
    protected TlsWordType getTargetSpecificEffectivelyLastSent(
            TlsWordType actualLastSent,
            List<TlsWord> messageStack,
            ContextPropertyContainer propertyContainer) {
        if (actualLastSent == TlsWordType.HELLO_REQUEST
                && propertyContainer.doPropertiesApply(ContextProperty.HANDSHAKE_UNFINISHED)
                && !getPreviousState()
                        .getContextPropertiesReached()
                        .contains(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)) {
            // HelloRequests during the handshake may be ignored and should not limit our options
            // note that we must respect the Hello Request if it lead us to a new handshake as this
            // means we have
            // other options
            return getLastInputNotMatchingType(messageStack, TlsWordType.HELLO_REQUEST);
        } else if (TlsWordType.effectivelyEquals(actualLastSent, TlsWordType.ANY_APP_DATA)
                && propertyContainer.doPropertiesApply(
                        ContextProperty.HANDSHAKE_UNFINISHED,
                        ContextProperty.ACCEPTED_RENEGOTIATION,
                        ContextProperty.NOT_CLIENT_LEARNER_SERVER_HELLO_SENT)) {
            // During a renegotiation triggered by us or the client, there may be app data
            // between the CH and the SH. This should not change our options
            return getLastInputNotMatchingType(messageStack, TlsWordType.ANY_APP_DATA);
        }
        return actualLastSent;
    }
}
