/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.analysis.transition;

import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.LetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.PoolLetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.SimpleLetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TlsLetterChainProvider;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;

public class ClientTlsLetterChains extends TlsLetterChainProvider {
    private static final LetterChain[] requiredTLS12LetterChains =
            new LetterChain[] {
                new SimpleLetterChain(null, TlsWordType.TLS12_SERVER_HELLO),
                new SimpleLetterChain(TlsWordType.TLS12_SERVER_HELLO, TlsWordType.CERTIFICATE),
                new SimpleLetterChain(
                        TlsWordType.CERTIFICATE,
                        TlsWordType.SERVER_KEY_EXCHANGE,
                        ContextProperty.IS_EPHEMERAL_HANDSHAKE),
                new SimpleLetterChain(
                        TlsWordType.SERVER_KEY_EXCHANGE,
                        TlsWordType.SERVER_HELLO_DONE,
                        ContextProperty.IS_EPHEMERAL_HANDSHAKE),
                new SimpleLetterChain(
                        TlsWordType.CERTIFICATE,
                        TlsWordType.SERVER_HELLO_DONE,
                        ContextProperty.NOT_IS_EPHEMERAL_HANDSHAKE),
                new SimpleLetterChain(TlsWordType.SERVER_HELLO_DONE, TlsWordType.ANY_CCS),
                new SimpleLetterChain(
                        TlsWordType.CCS, TlsWordType.FINISHED, ContextProperty.IS_TLS12_FLOW),
                new PoolLetterChain(
                        TlsWordType.FINISHED,
                        ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                        TlsWordType.ANY_APP_DATA),
                new SimpleLetterChain(
                        TlsWordType.TLS12_SERVER_HELLO,
                        TlsWordType.ANY_CCS,
                        ContextProperty.IN_RESUMPTION_FLOW),
            };

    private static final LetterChain[] requiredTLS13LetterChains =
            new LetterChain[] {
                new SimpleLetterChain(null, TlsWordType.TLS13_SERVER_HELLO),
                new SimpleLetterChain(
                        TlsWordType.TLS13_SERVER_HELLO, TlsWordType.ENCRYPTED_EXTENSIONS),
                new SimpleLetterChain(TlsWordType.ENCRYPTED_EXTENSIONS, TlsWordType.CERTIFICATE),
                new SimpleLetterChain(TlsWordType.CERTIFICATE, TlsWordType.CERTIFICATE_VERIFY),
                new SimpleLetterChain(TlsWordType.CERTIFICATE_VERIFY, TlsWordType.FINISHED),
                new PoolLetterChain(
                        TlsWordType.FINISHED,
                        ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                        TlsWordType.ANY_APP_DATA,
                        TlsWordType.NEW_SESSION_TICKET),
            };

    @Override
    public LetterChain[] getOptionalTLS12LetterChains() {
        LetterChain[] optionalTransitions =
                new LetterChain[] {
                    new SimpleLetterChain(TlsWordType.FINISHED, TlsWordType.HELLO_REQUEST),
                    new SimpleLetterChain(TlsWordType.ANY_APP_DATA, TlsWordType.HELLO_REQUEST),
                    new SimpleLetterChain(
                            TlsWordType.HELLO_REQUEST,
                            TlsWordType.TLS12_SERVER_HELLO,
                            ContextProperty.ACCEPTED_RENEGOTIATION),
                    // clients may ignore the HelloRequest
                    new SimpleLetterChain(
                            TlsWordType.ANY,
                            TlsWordType.HELLO_REQUEST,
                            ContextProperty.HANDSHAKE_UNFINISHED),

                    // clients may allow an overlap between a started renegotiation and sending the
                    // server hello
                    new SimpleLetterChain(
                            TlsWordType.ANY,
                            TlsWordType.ANY_APP_DATA,
                            ContextProperty.ACCEPTED_RENEGOTIATION,
                            ContextProperty.NOT_CLIENT_LEARNER_SERVER_HELLO_SENT),
                    new SimpleLetterChain(
                            TlsWordType.CERTIFICATE,
                            TlsWordType.CERTIFICATE_REQUEST,
                            ContextProperty.NOT_IS_EPHEMERAL_HANDSHAKE),
                    new SimpleLetterChain(
                            TlsWordType.SERVER_KEY_EXCHANGE,
                            TlsWordType.CERTIFICATE_REQUEST,
                            ContextProperty.IS_EPHEMERAL_HANDSHAKE),
                    new SimpleLetterChain(
                            TlsWordType.CERTIFICATE_REQUEST, TlsWordType.SERVER_HELLO_DONE)
                };

        for (LetterChain chain : optionalTransitions) {
            chain.setRequired(false);
        }
        return optionalTransitions;
    }

    @Override
    public LetterChain[] getRequiredTLS12LetterChains() {
        return requiredTLS12LetterChains;
    }

    @Override
    public LetterChain[] getRequiredTLS13LetterChains() {
        return requiredTLS13LetterChains;
    }

    @Override
    public LetterChain[] getOptionalTLS13LetterChains() {
        LetterChain[] optionalTransitions =
                new LetterChain[] {
                    new SimpleLetterChain(null, TlsWordType.HELLO_RETRY_REQUEST),
                    new SimpleLetterChain(
                            TlsWordType.ANY,
                            TlsWordType.ANY_CCS,
                            ContextProperty.HANDSHAKE_UNFINISHED),
                    new SimpleLetterChain(TlsWordType.FINISHED, TlsWordType.KEY_UPDATE),
                    new SimpleLetterChain(TlsWordType.ANY_APP_DATA, TlsWordType.KEY_UPDATE),

                    // some libraries may allow the hello request early in the handshake
                    new SimpleLetterChain(
                            TlsWordType.ANY,
                            TlsWordType.HELLO_REQUEST,
                            ContextProperty.NOT_FINISHED_SENT)
                };

        for (LetterChain chain : optionalTransitions) {
            chain.setRequired(false);
        }
        return optionalTransitions;
    }
}
