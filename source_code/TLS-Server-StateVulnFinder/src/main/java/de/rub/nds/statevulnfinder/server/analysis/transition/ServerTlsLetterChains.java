/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.analysis.transition;

import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.LetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.MultiLetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.PoolLetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.SimpleLetterChain;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TlsLetterChainProvider;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;

/**
 * Models allowed subsequent inputs for a given immediate previous input Note that the subsequent
 * inputs are only allowed if the chain up to this point was valid
 */
public class ServerTlsLetterChains extends TlsLetterChainProvider {
    private static final LetterChain[] requiredTLS12LetterChains =
            new LetterChain[] {
                new SimpleLetterChain(null, TlsWordType.TLS12_CLIENT_HELLO),

                // note that all initial letter chains must be limited to an unfinished handshake
                // this way we can ensure that upon a rejected renegotiation attempt
                // we do not expect the usual handshake transitions despite being in
                // the finished state
                new SimpleLetterChain(
                        TlsWordType.TLS12_CLIENT_HELLO,
                        TlsWordType.CLIENT_KEY_EXCHANGE,
                        ContextProperty.NOT_CLIENT_AUTH_REQUESTED,
                        ContextProperty.HANDSHAKE_UNFINISHED),
                new SimpleLetterChain(
                        TlsWordType.TLS12_CLIENT_HELLO,
                        TlsWordType.BLEICHENBACHER,
                        ContextProperty.NOT_CLIENT_AUTH_REQUESTED,
                        ContextProperty.HANDSHAKE_UNFINISHED),

                // client auth
                new SimpleLetterChain(
                        TlsWordType.TLS12_CLIENT_HELLO,
                        TlsWordType.EMPTY_CERTIFICATE,
                        ContextProperty.CLIENT_AUTH_REQUESTED,
                        ContextProperty.HANDSHAKE_UNFINISHED),
                new SimpleLetterChain(
                        TlsWordType.EMPTY_CERTIFICATE,
                        TlsWordType.CLIENT_KEY_EXCHANGE,
                        ContextProperty.CLIENT_AUTH_REQUESTED,
                        ContextProperty.HANDSHAKE_UNFINISHED),
                new SimpleLetterChain(
                        TlsWordType.EMPTY_CERTIFICATE,
                        TlsWordType.BLEICHENBACHER,
                        ContextProperty.CLIENT_AUTH_REQUESTED,
                        ContextProperty.HANDSHAKE_UNFINISHED),
                // our cert is supposed to be empty but it currently isn't
                new SimpleLetterChain(
                        TlsWordType.CLIENT_KEY_EXCHANGE,
                        TlsWordType.CERTIFICATE_VERIFY,
                        ContextProperty.CLIENT_AUTH_REQUESTED),
                new SimpleLetterChain(
                        TlsWordType.BLEICHENBACHER,
                        TlsWordType.CERTIFICATE_VERIFY,
                        ContextProperty.CLIENT_AUTH_REQUESTED),
                // Our Cert shouldn't be known to any server so it should be rejected but some
                // servers accept it
                new SimpleLetterChain(
                        TlsWordType.CERTIFICATE_VERIFY,
                        TlsWordType.ANY_CCS,
                        ContextProperty.CLIENT_AUTH_REQUESTED),
                new SimpleLetterChain(
                        TlsWordType.CLIENT_KEY_EXCHANGE,
                        TlsWordType.ANY_CCS,
                        ContextProperty.NOT_CLIENT_AUTH_REQUESTED),
                new SimpleLetterChain(
                        TlsWordType.BLEICHENBACHER,
                        TlsWordType.ANY_CCS,
                        ContextProperty.NOT_CLIENT_AUTH_REQUESTED),
                // todo: drop all handshake-lifetime properties upon completing a handshake?
                new SimpleLetterChain(
                        TlsWordType.RESUMING_HELLO,
                        TlsWordType.ANY_CCS,
                        ContextProperty.IN_RESUMPTION_FLOW,
                        ContextProperty.HANDSHAKE_UNFINISHED),

                // do not allow a CCS, FIN sequence right from start - a TLS 1.2 hello must have
                // been sent
                // note that this is not an expected benign transition when we're on a BB path
                new SimpleLetterChain(
                        TlsWordType.CCS,
                        TlsWordType.FINISHED,
                        ContextProperty.IS_TLS12_FLOW,
                        ContextProperty.NOT_BLEICHENBACHER_PATH),

                // a handshake _FINISHED_CORRECTLY if it is a benign flow and not BB
                new PoolLetterChain(
                        TlsWordType.FINISHED,
                        ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                        TlsWordType.ANY_APP_DATA),
                new SimpleLetterChain(
                        TlsWordType.RESET_CONNECTION,
                        TlsWordType.RESUMING_HELLO,
                        ContextProperty.CAN_RESUME_CORRECTLY_TLS12),
                new SimpleLetterChain(TlsWordType.RESET_CONNECTION, TlsWordType.TLS12_CLIENT_HELLO),
                new SimpleLetterChain(TlsWordType.ANY, TlsWordType.RESET_CONNECTION),
            };

    private static final LetterChain[] requiredTLS13LetterChains =
            new LetterChain[] {
                new SimpleLetterChain(null, TlsWordType.TLS13_CLIENT_HELLO),
                new SimpleLetterChain(null, TlsWordType.HRR_ENFORCING_HELLO),
                new SimpleLetterChain(
                        TlsWordType.HRR_ENFORCING_HELLO, TlsWordType.TLS13_CLIENT_HELLO),
                new SimpleLetterChain(
                        TlsWordType.TLS13_CLIENT_HELLO,
                        TlsWordType.FINISHED,
                        ContextProperty.HANDSHAKE_UNFINISHED,
                        ContextProperty.NOT_CLIENT_AUTH_REQUESTED),

                // optional client auth
                new SimpleLetterChain(
                        TlsWordType.TLS13_CLIENT_HELLO,
                        TlsWordType.EMPTY_CERTIFICATE,
                        ContextProperty.CLIENT_AUTH_REQUESTED),
                new SimpleLetterChain(
                        TlsWordType.EMPTY_CERTIFICATE,
                        TlsWordType.CERTIFICATE_VERIFY,
                        ContextProperty.CLIENT_AUTH_REQUESTED),
                new SimpleLetterChain(TlsWordType.RESUMING_HELLO, TlsWordType.FINISHED),
                new PoolLetterChain(
                        TlsWordType.FINISHED, TlsWordType.KEY_UPDATE, TlsWordType.ANY_APP_DATA),
                new SimpleLetterChain(
                        TlsWordType.RESET_CONNECTION,
                        TlsWordType.RESUMING_HELLO,
                        ContextProperty.CAN_RESUME_CORRECTLY_TLS13),
                new SimpleLetterChain(TlsWordType.RESET_CONNECTION, TlsWordType.TLS13_CLIENT_HELLO),
                new SimpleLetterChain(
                        TlsWordType.RESET_CONNECTION, TlsWordType.HRR_ENFORCING_HELLO),
                new SimpleLetterChain(TlsWordType.ANY, TlsWordType.RESET_CONNECTION),
            };

    @Override
    public LetterChain[] getOptionalTLS13LetterChains() {
        LetterChain[] optionalTransitions =
                new LetterChain[] {
                    new SimpleLetterChain(
                            TlsWordType.ANY,
                            TlsWordType.ANY_CCS,
                            ContextProperty.HANDSHAKE_UNFINISHED),
                    // generally allowed heartbeat
                    new SimpleLetterChain(TlsWordType.ANY, TlsWordType.HEARTBEAT)
                };
        for (LetterChain chain : optionalTransitions) {
            chain.setRequired(false);
        }
        return optionalTransitions;
    }

    @Override
    public LetterChain[] getOptionalTLS12LetterChains() {
        // We generally allow TLS 1.3 CH messages sent after a TLS 1.2 handshake
        // since a server may ignore / reject with alert any CH message without
        // further inspection if renegotiation is not supported.
        // To avoid accepting TLS 1.3 flows after a TLS 1.2 handshake, our
        // ContextPropertyContainer does not switch to TLS 1.3 mode when a
        // 1.2 handshake was started. This also ensures that ExpectedResponses
        // of TLS 1.3 are not applied in this case.
        TlsWordType[] allowedAfterHandshake =
                new TlsWordType[] {
                    TlsWordType.TLS12_CLIENT_HELLO,
                    TlsWordType.HRR_ENFORCING_HELLO,
                    TlsWordType.TLS13_CLIENT_HELLO,
                    TlsWordType.ANY_APP_DATA
                };
        LetterChain[] optionalTransitions =
                new LetterChain[] {
                    // we add app data as optional in all of these cases, however, it may also be
                    // defined as required
                    // for some of the inputs (e.g after Fin); Handshake Finished Correctly ensures
                    // that we did not commence a new handshake
                    new MultiLetterChain(
                            TlsWordType.FINISHED,
                            ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                            allowedAfterHandshake),
                    new MultiLetterChain(
                            TlsWordType.ANY_APP_DATA,
                            ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                            allowedAfterHandshake),
                    // a client hello does not change our options if it was rejected / ignored
                    // however, some servers close the connection upon renegotiation, hence it is
                    // optional
                    new MultiLetterChain(
                            TlsWordType.ANY_CLIENT_HELLO,
                            ContextProperty.REJECTED_RENEGOTIATION,
                            allowedAfterHandshake),

                    // resumption condition is unique to RESUMING_HELLO
                    new SimpleLetterChain(
                            TlsWordType.ANY_APP_DATA,
                            TlsWordType.RESUMING_HELLO,
                            ContextProperty.CAN_RESUME_CORRECTLY_TLS12),
                    new SimpleLetterChain(
                            TlsWordType.FINISHED,
                            TlsWordType.RESUMING_HELLO,
                            ContextProperty.CAN_RESUME_CORRECTLY_TLS12),
                    new SimpleLetterChain(
                            TlsWordType.ANY_CLIENT_HELLO,
                            TlsWordType.RESUMING_HELLO,
                            ContextProperty.REJECTED_RENEGOTIATION,
                            ContextProperty.CAN_RESUME_CORRECTLY_TLS12),
                    new SimpleLetterChain(
                            TlsWordType.HEARTBEAT,
                            TlsWordType.RESUMING_HELLO,
                            ContextProperty.CAN_RESUME_CORRECTLY_TLS12),

                    // generally allowed heartbeat
                    new SimpleLetterChain(TlsWordType.ANY, TlsWordType.HEARTBEAT),
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
}
