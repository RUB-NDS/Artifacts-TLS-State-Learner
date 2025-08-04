/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.LinkedList;

public class ResetConnectionWord extends TlsWord {

    public ResetConnectionWord() {
        super(TlsWordType.RESET_CONNECTION);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        ResetConnectionAction resetConnectionAction =
                new ResetConnectionAction(state.getTlsContext().getConnection().getAlias());
        resetConnectionAction.execute(state);
        return new ResponseFingerprint(new LinkedList<>(), new LinkedList<>(), SocketState.UP);
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
        return "ResetConnection";
    }

    @Override
    public String toShortString() {
        return "RST";
    }
}
