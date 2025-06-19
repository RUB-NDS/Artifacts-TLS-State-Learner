/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.analysis.transition;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextPropertyContainer;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import java.util.List;

public class ServerContextPropertyContainer extends ContextPropertyContainer {

    CipherSuite lastSelectedCipherSuite = null;

    public ServerContextPropertyContainer(StateMachine stateMachine) {
        super(stateMachine);
    }

    @Override
    protected void updateContextForResponse(TlsWord concreteMessageSent) {
        if (isRejectedRenegotiation(concreteMessageSent)) {
            setContextProperties(ContextProperty.REJECTED_RENEGOTIATION);
            return;
        } else if (concreteMessageSent.getType() == TlsWordType.ANY_CLIENT_HELLO
                && !isRejectedRenegotiation(concreteMessageSent)) {
            setContextProperties(ContextProperty.ACCEPTED_RENEGOTIATION);
        }

        List<ProtocolMessage> responses = queryStateMachine(concreteMessageSent);

        checkForReceivedFinished(responses);

        if (responses.stream().anyMatch(ServerHelloMessage.class::isInstance)) {
            ServerHelloMessage serverHelloReceived =
                    (ServerHelloMessage)
                            responses.stream()
                                    .filter(ServerHelloMessage.class::isInstance)
                                    .findFirst()
                                    .orElse(null);
            lastSelectedCipherSuite =
                    CipherSuite.getCipherSuite(
                            serverHelloReceived.getSelectedCipherSuite().getValue());

            if (responses.stream().anyMatch(CertificateMessage.class::isInstance)) {
                setContextProperties(ContextProperty.NOT_IN_RESUMPTION_FLOW);
            }

            if (responses.stream().anyMatch(CertificateRequestMessage.class::isInstance)) {
                setContextProperties(ContextProperty.CLIENT_AUTH_REQUESTED);
            } else {
                setContextProperties(ContextProperty.NOT_CLIENT_AUTH_REQUESTED);
            }
        }

        checkForFinishedHandshake();
        determineResumptionProperties(responses);
    }

    @Override
    public void updateContextForSent(TlsWord concreteMessageSent) {
        if (isRejectedRenegotiation(concreteMessageSent)
                || isRenegotiationToleranceTls13Hello(concreteMessageSent)) {
            // don't update anything - we're still in a finished handshake
            return;
        }

        checkForFinishedHandshake();
        TlsWordType messageTypeSent = concreteMessageSent.getType();
        switch (messageTypeSent) {
            case HRR_ENFORCING_HELLO:
            case TLS12_CLIENT_HELLO:
            case TLS13_CLIENT_HELLO:
                handshakeStartedPropertyUpdate();
                updateHelloProperties(messageTypeSent, concreteMessageSent);
                break;
            case RESUMING_HELLO:
                handshakeStartedPropertyUpdate();
                newResumptionHandshakePropertyUpdate((ResumingClientHelloWord) concreteMessageSent);
                break;
            case RESET_CONNECTION:
                connectionResetPropertyUpdate();
                break;
            case BLEICHENBACHER:
                setContextProperties(ContextProperty.BLEICHENBACHER_PATH);
                break;
            case FINISHED:
                setContextProperties(ContextProperty.FINISHED_SENT);
                break;
            case HEARTBEAT:
                if (!doPropertiesApply(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)) {
                    setContextProperties(ContextProperty.EARLY_HEARTBEAT_SENT);
                }
            case DUMMY_CCS:
            case CCS:
                setContextProperties(ContextProperty.CCS_SENT);
                break;
            default:
        }
    }

    private void determineResumptionProperties(List<ProtocolMessage> responses) {
        if (responses.stream().anyMatch(NewSessionTicketMessage.class::isInstance)) {
            // Ticket must have arrived with CCS in TLS 1.2
            if (doPropertiesApply(ContextProperty.IS_TLS12_FLOW)
                    && responses.stream().anyMatch(ChangeCipherSpecMessage.class::isInstance)) {
                setContextProperties(ContextProperty.RECEIVED_TICKET);
                // note that RFC 5077 explicitly allows using a ticket obtained
                // in session resumption before sending Client Fin
                setContextProperties(ContextProperty.CAN_RESUME_CORRECTLY_TLS12);
            } else if (doPropertiesApply(ContextProperty.IS_TLS13_FLOW)
                    && doPropertiesApply(ContextProperty.FINISHED_RECEIVED)) {
                setContextProperties(ContextProperty.RECEIVED_TICKET);
                // as for TLS 1.2, it's also allowed to immediately use a ticket
                // received before sending Client Fin
                // todo: tls attacker cant do this
                setContextProperties(ContextProperty.CAN_RESUME_CORRECTLY_TLS13);
            }
        }

        if (responses.stream().anyMatch(ServerHelloMessage.class::isInstance)
                && doPropertiesApply(ContextProperty.IS_TLS12_FLOW)) {
            ServerHelloMessage serverHello =
                    (ServerHelloMessage)
                            responses.stream()
                                    .filter(ServerHelloMessage.class::isInstance)
                                    .findFirst()
                                    .orElse(null);
            if (serverHello.getSessionIdLength().getValue() > 0) {
                setContextProperties(ContextProperty.RECEIVED_SESSION_ID);
            }
        }

        if (doPropertiesApply(
                ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                ContextProperty.IS_TLS12_FLOW,
                ContextProperty.RECEIVED_SESSION_ID)) {
            setContextProperties(ContextProperty.CAN_RESUME_CORRECTLY_TLS12);
        }
    }

    private void newResumptionHandshakePropertyUpdate(ResumingClientHelloWord concreteMessageSent) {
        if (doPropertiesApply(ContextProperty.CAN_RESUME_CORRECTLY_TLS12)) {
            setContextProperties(ContextProperty.IS_TLS12_FLOW);
        } else {
            setContextProperties(ContextProperty.IS_TLS13_FLOW);
        }
        setContextProperties(ContextProperty.IN_RESUMPTION_FLOW);
        if (concreteMessageSent.isIncludeSessionTicketExtension()) {
            setContextProperties(ContextProperty.OFFERED_SESSION_TICKET_EXTENSION);
        }
        if (lastSelectedCipherSuite != null
                && !lastSelectedCipherSuite.isTLS13()
                && lastSelectedCipherSuite.isEphemeral()) {
            setContextProperties(ContextProperty.IS_EPHEMERAL_HANDSHAKE);
        }
    }

    private void updateHelloProperties(TlsWordType type, TlsWord messageSent) {
        // a full handshake resets our stored sessions
        removeContextProperties(
                ContextProperty.CAN_RESUME_CORRECTLY_TLS12,
                ContextProperty.CAN_RESUME_CORRECTLY_TLS13);
        if (type == TlsWordType.TLS12_CLIENT_HELLO) {
            setContextProperties(ContextProperty.IS_TLS12_FLOW);
            ClientHelloWord helloSent = (ClientHelloWord) messageSent;
            if (helloSent.getSuite().isEphemeral()) {
                setContextProperties(ContextProperty.IS_EPHEMERAL_HANDSHAKE);
            }

            if (helloSent.isIncludeSessionTicketExtension()) {
                setContextProperties(ContextProperty.OFFERED_SESSION_TICKET_EXTENSION);
            }
        } else if (type == TlsWordType.TLS13_CLIENT_HELLO
                || type == TlsWordType.HRR_ENFORCING_HELLO) {
            setContextProperties(ContextProperty.IS_TLS13_FLOW);
        }
    }

    private boolean isRejectedRenegotiation(TlsWord concreteMessageSent) {
        List<ProtocolMessage> receivedMessages = queryStateMachine(concreteMessageSent);
        if (TlsWordType.effectivelyEquals(
                        concreteMessageSent.getType(), TlsWordType.ANY_CLIENT_HELLO)
                && doPropertiesApply(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)) {
            if (receivedMessages.isEmpty()) {
                return true;
            }
            if (receivedMessages.size() == 1 && receivedMessages.get(0) instanceof AlertMessage) {
                AlertMessage alert = (AlertMessage) receivedMessages.get(0);
                return alert.getLevel().getValue() == AlertLevel.WARNING.getValue();
            }
        }
        return false;
    }

    private boolean isRenegotiationToleranceTls13Hello(TlsWord concreteMessageSent) {
        // we allow sending TLS 1.3 Hellos after a finished TLS 1.2 handshake
        // since a server may reject it with no_renegotiation alert before
        // checking its content - however, we do not adjust the context properties
        // for these hellos since we must never actually commence a TLS 1.3
        // session from there on
        return (concreteMessageSent.getType() == TlsWordType.TLS13_CLIENT_HELLO
                        || concreteMessageSent.getType() == TlsWordType.HRR_ENFORCING_HELLO)
                && doPropertiesApply(
                        ContextProperty.IS_TLS12_FLOW,
                        ContextProperty.HANDSHAKE_FINISHED_CORRECTLY);
    }
}
