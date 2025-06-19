/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.function.Predicate;

public class ClientKeyExchangeWord extends TlsWord {

    private static final NamedGroup ECDH_FALLBACK_NAMED_GROUP = NamedGroup.SECP256R1;

    public ClientKeyExchangeWord() {
        super(TlsWordType.CLIENT_KEY_EXCHANGE);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        if (AlgorithmResolver.getKeyExchangeAlgorithm(
                        state.getTlsContext().getChooser().getSelectedCipherSuite())
                == null) {
            // explicit message for TLS 1.3 cipher suites to avoid non-sending
            sendMessage(new RSAClientKeyExchangeMessage(), new Record(), state);
        } else {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(
                            state.getTlsContext().getChooser().getSelectedCipherSuite())
                    .isEC()) {
                ensureAppropriateNamedGroup(state);
            }
            SendDynamicClientKeyExchangeAction sendCkeAction =
                    new SendDynamicClientKeyExchangeAction(
                            state.getTlsContext().getConnection().getAlias());
            sendCkeAction.execute(state);
        }

        return receiveMessages(state, receiveHint);
    }

    /**
     * If we send a DHE SKE message, we adjust the selected NamedGroup to an FFDHE one causing
     * problems for a subsequent ECDH CKE message. We therefor attempt to fix these cases by
     * selecting an elliptic curve from the supported values. If no such curve can be found, we use
     * the NamedGroup defined above.
     *
     * @param state
     */
    private void ensureAppropriateNamedGroup(State state) {
        if (!state.getTlsContext().getChooser().getSelectedNamedGroup().isCurve()) {
            NamedGroup betterNamedGroup =
                    state.getConfig().getDefaultClientNamedGroups().stream()
                            .filter(NamedGroup::isCurve)
                            .filter(Predicate.not(NamedGroup::isGost))
                            .findFirst()
                            .orElse(ECDH_FALLBACK_NAMED_GROUP);
            state.getTlsContext().setSelectedGroup(betterNamedGroup);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        return hash;
    }

    @Override
    public String toString() {
        return "ClientKeyExchange";
    }

    @Override
    public String toShortString() {
        return "CKE";
    }
}
