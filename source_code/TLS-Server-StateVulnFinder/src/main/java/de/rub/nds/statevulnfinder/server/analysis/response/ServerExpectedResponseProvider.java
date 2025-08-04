/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.analysis.response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedMessage;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponse;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponseProvider;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import java.util.List;

public class ServerExpectedResponseProvider extends ExpectedResponseProvider {

    private final ExpectedResponse[] expectedTls12ServerResponses =
            new ExpectedResponse[] {
                new ExpectedResponse(TlsWordType.ANY_CCS),
                new ExpectedResponse(TlsWordType.CLIENT_KEY_EXCHANGE),
                new ExpectedResponse(TlsWordType.BLEICHENBACHER),

                // resumption
                new ExpectedResponse(
                        TlsWordType.RESUMING_HELLO,
                        ContextProperty.CAN_RESUME_CORRECTLY_TLS12,
                        ServerHelloMessage.class,
                        ChangeCipherSpecMessage.class,
                        FinishedMessage.class),
                new ExpectedResponse(TlsWordType.RESET_CONNECTION),

                // there may be a no-renegotiation alert or no response (even for TLS 1.3 messages)
                new ExpectedResponse(
                        TlsWordType.ANY_CLIENT_HELLO,
                        ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                        AlertMessage.class),
                new ExpectedResponse(
                        TlsWordType.ANY_CLIENT_HELLO, ContextProperty.HANDSHAKE_FINISHED_CORRECTLY),

                // optional client-auth
                new ExpectedResponse(TlsWordType.EMPTY_CERTIFICATE),
                new ExpectedResponse(
                        TlsWordType.CERTIFICATE_VERIFY, ContextProperty.CLIENT_AUTH_REQUESTED)
            };

    private final ExpectedResponse[] expectedTls13ServerResponses =
            new ExpectedResponse[] {
                new ExpectedResponse(TlsWordType.EMPTY_CERTIFICATE),
                new ExpectedResponse(TlsWordType.CERTIFICATE_VERIFY),
                new ExpectedResponse(TlsWordType.RESET_CONNECTION),
                new ExpectedResponse(TlsWordType.ANY_CCS),
                new ExpectedResponse(TlsWordType.KEY_UPDATE, KeyUpdateMessage.class),
                // key update is often ignored
                new ExpectedResponse(TlsWordType.KEY_UPDATE)
            };

    private final ExpectedResponse[] expectedSharedServerResponses =
            new ExpectedResponse[] {
                new ExpectedResponse(TlsWordType.HEARTBEAT),
                new ExpectedResponse(TlsWordType.HEARTBEAT, HeartbeatMessage.class)
            };

    @Override
    public ExpectedResponse[] getExpectedTls12Responses() {
        return ArrayConverter.concatenate(
                getTls12HelloResponses(),
                getTls12ResponsesWithAppData(),
                expectedTls12ServerResponses,
                expectedSharedServerResponses);
    }

    @Override
    public ExpectedResponse[] getExpectedTls13Responses() {
        return ArrayConverter.concatenate(
                getTls13HelloResponses(),
                getTls13ResponsesWithAppData(),
                expectedTls13ServerResponses,
                expectedSharedServerResponses);
    }

    private ExpectedResponse[] getTls12HelloResponses() {
        ExpectedResponse[] expectedResponses =
                new ExpectedResponse[] {
                    new ExpectedResponse(
                            TlsWordType.TLS12_CLIENT_HELLO,
                            ContextProperty.IS_EPHEMERAL_HANDSHAKE,
                            ServerHelloMessage.class,
                            CertificateMessage.class,
                            ServerKeyExchangeMessage.class,
                            ServerHelloDoneMessage.class),
                    new ExpectedResponse(
                            TlsWordType.TLS12_CLIENT_HELLO,
                            ContextProperty.NOT_IS_EPHEMERAL_HANDSHAKE,
                            ServerHelloMessage.class,
                            CertificateMessage.class,
                            ServerHelloDoneMessage.class)
                };
        addOptionalCertificateRequests(expectedResponses);
        return expectedResponses;
    }

    private ExpectedResponse[] getTls13HelloResponses() {
        ExpectedResponse[] expectedResponses =
                new ExpectedResponse[] {
                    new ExpectedResponse(
                            TlsWordType.TLS13_CLIENT_HELLO,
                            ServerHelloMessage.class,
                            EncryptedExtensionsMessage.class,
                            CertificateMessage.class,
                            CertificateVerifyMessage.class,
                            FinishedMessage.class),
                    new ExpectedResponse(TlsWordType.HRR_ENFORCING_HELLO, ServerHelloMessage.class),
                    // note that the code flow allows a server to perform a full handshake even upon
                    // PSK resumption
                    new ExpectedResponse(
                            TlsWordType.TLS13_RESUMING_HELLO,
                            ContextProperty.CAN_RESUME_CORRECTLY_TLS13,
                            ServerHelloMessage.class,
                            EncryptedExtensionsMessage.class,
                            FinishedMessage.class)
                };

        // add optional CCS messages
        for (ExpectedResponse expected : expectedResponses) {
            expected.getExpectedMessages()
                    .add(1, new ExpectedMessage(ChangeCipherSpecMessage.class, false));
        }

        // allow early NewSessionTickets sent with server's Fin
        for (ExpectedResponse expectedResponse : expectedResponses) {
            if (expectedResponse.getExpectedMessages().stream()
                    .map(ExpectedMessage::getMessage)
                    .anyMatch(NewSessionTicketMessage.class::isAssignableFrom)) {
                ExpectedMessage optionalEarlyTicket =
                        new ExpectedMessage(NewSessionTicketMessage.class, false, true);
                expectedResponse.getExpectedMessages().add(optionalEarlyTicket);
            }
        }

        addOptionalCertificateRequests(expectedResponses);
        return expectedResponses;
    }

    /**
     * Looks for predecessors (SKE, EE, CERT) of optional CertRequest messages
     *
     * @param expectedResponses the predefined responses without cert requests
     */
    private void addOptionalCertificateRequests(ExpectedResponse[] expectedResponses) {
        ExpectedMessage optionalCertRequest =
                new ExpectedMessage(CertificateRequestMessage.class, false);
        for (ExpectedResponse expectedResponse : expectedResponses) {
            List<ExpectedMessage> expectedMessages = expectedResponse.getExpectedMessages();
            int inclusionIndex = -1;
            ExpectedMessage serverKeyExchange =
                    expectedMessages.stream()
                            .filter(
                                    expected ->
                                            expected.getMessage() == ServerKeyExchangeMessage.class)
                            .findFirst()
                            .orElse(null);
            ExpectedMessage encExtensions =
                    expectedMessages.stream()
                            .filter(
                                    expected ->
                                            expected.getMessage()
                                                    == EncryptedExtensionsMessage.class)
                            .findFirst()
                            .orElse(null);
            ExpectedMessage certificate =
                    expectedMessages.stream()
                            .filter(expected -> expected.getMessage() == CertificateMessage.class)
                            .findFirst()
                            .orElse(null);

            if (serverKeyExchange != null) {
                inclusionIndex = expectedMessages.indexOf(serverKeyExchange) + 1;
            } else if (encExtensions != null) {
                inclusionIndex = expectedMessages.indexOf(encExtensions) + 1;
            } else if (certificate != null) {
                inclusionIndex = expectedMessages.indexOf(certificate) + 1;
            }

            if (inclusionIndex > -1) {
                expectedMessages.add(inclusionIndex, optionalCertRequest);
            }
        }
    }

    private ExpectedResponse[] getTls13ResponsesWithAppData() {
        TlsWordType[] ignorableMessageTypes =
                new TlsWordType[] {
                    TlsWordType.ANY_APP_DATA, TlsWordType.NEW_SESSION_TICKET, TlsWordType.KEY_UPDATE
                };
        ExpectedResponse[] expectedResponses =
                new ExpectedResponse[] {
                    new ExpectedResponse(TlsWordType.FINISHED),
                    new ExpectedResponse(TlsWordType.ANY_APP_DATA)
                };

        for (ExpectedResponse expected : expectedResponses) {
            expected.setIgnorableTypes(ignorableMessageTypes);
        }
        return expectedResponses;
    }

    private ExpectedResponse[] getTls12ResponsesWithAppData() {
        TlsWordType[] ignorableMessageTypes = new TlsWordType[] {TlsWordType.ANY_APP_DATA};
        ExpectedResponse[] expectedResponses =
                new ExpectedResponse[] {
                    new ExpectedResponse(
                            TlsWordType.FINISHED,
                            ContextProperty.NOT_IN_RESUMPTION_FLOW,
                            ChangeCipherSpecMessage.class,
                            FinishedMessage.class),
                    new ExpectedResponse(TlsWordType.FINISHED, ContextProperty.IN_RESUMPTION_FLOW),
                    new ExpectedResponse(
                            TlsWordType.FINISHED,
                            ContextProperty.OFFERED_SESSION_TICKET_EXTENSION,
                            NewSessionTicketMessage.class,
                            ChangeCipherSpecMessage.class,
                            FinishedMessage.class),
                    new ExpectedResponse(TlsWordType.ANY_APP_DATA)
                };

        for (ExpectedResponse expected : expectedResponses) {
            expected.setIgnorableTypes(ignorableMessageTypes);
        }
        return expectedResponses;
    }
}
