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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class ServerKeyExchangeWord extends TlsWord {

    public ServerKeyExchangeWord() {
        super(TlsWordType.SERVER_KEY_EXCHANGE);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        if (!state.getTlsContext().getChooser().getSelectedCipherSuite().isEphemeral()
                || AlgorithmResolver.getKeyExchangeAlgorithm(
                                state.getTlsContext().getChooser().getSelectedCipherSuite())
                        == null) {
            // explicit message for TLS 1.3 cipher suites and static cipher suites to avoid
            // non-sending
            sendMessage(new DHEServerKeyExchangeMessage(), new Record(), state);
        } else {
            SendDynamicServerKeyExchangeAction sendSkeAction =
                    new SendDynamicServerKeyExchangeAction(
                            state.getTlsContext().getConnection().getAlias());
            sendSkeAction.execute(state);
        }

        return receiveMessages(state, receiveHint);
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
        return "ServerKeyExchange";
    }

    @Override
    public String toShortString() {
        return "SKE";
    }
}
