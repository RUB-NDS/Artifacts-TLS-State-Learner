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
import de.rub.nds.statevulnfinder.core.algorithm.words.ServerHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextPropertyContainer;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import java.util.List;

public class ClientContextPropertyContainer extends ContextPropertyContainer {

    public ClientContextPropertyContainer(StateMachine stateMachine) {
        super(stateMachine);
    }

    @Override
    public void updateContextForSent(TlsWord concreteMessageSent) {
        TlsWordType messageTypeSent = concreteMessageSent.getType();
        switch (messageTypeSent) {
            case TLS12_SERVER_HELLO:
                setContextProperties(ContextProperty.IS_TLS12_FLOW);
                setContextProperties(ContextProperty.CLIENT_LEARNER_SERVER_HELLO_SENT);
                ServerHelloWord serverHello = (ServerHelloWord) concreteMessageSent;
                if (serverHello.getSuite().isEphemeral()) {
                    setContextProperties(ContextProperty.IS_EPHEMERAL_HANDSHAKE);
                }
                break;
            case TLS13_SERVER_HELLO:
                setContextProperties(ContextProperty.IS_TLS13_FLOW);
                setContextProperties(ContextProperty.CLIENT_LEARNER_SERVER_HELLO_SENT);
                break;
            case FINISHED:
                setContextProperties(ContextProperty.FINISHED_SENT);
                checkForFinishedHandshake();
            default:
        }
    }

    @Override
    protected void updateContextForResponse(TlsWord concreteMessageSent) {
        List<ProtocolMessage> responses = queryStateMachine(concreteMessageSent);
        checkForRenegotiation(responses);
        checkForReceivedFinished(responses);
        checkForFinishedHandshake();
    }

    private void checkForRenegotiation(List<ProtocolMessage> responses) {
        if (doPropertiesApply(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)
                && responses.stream().anyMatch(ClientHelloMessage.class::isInstance)) {
            handshakeStartedPropertyUpdate();
            setContextProperties(
                    ContextProperty.IS_TLS12_FLOW, ContextProperty.ACCEPTED_RENEGOTIATION);
        }
    }
}
