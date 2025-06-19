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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ResetConnectionWord extends TlsWord {
    private static Long lastMsTimestamp = 0L;
    private static final Logger LOG = LogManager.getLogger();

    public ResetConnectionWord() {
        super(TlsWordType.RESET_CONNECTION);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        ResetConnectionAction resetConnectionAction =
                new ResetConnectionAction(state.getTlsContext().getConnection().getAlias(), 10);
        int attempts = 0;
        do {
            if (attempts > 0) {
                sleepFor100ms();
            }

            resetConnectionAction.reset();
            resetConnectionAction.execute(state);
            attempts++;
        } while (!resetConnectionAction.executedAsPlanned() && attempts < 10);
        long currentMs = System.currentTimeMillis();
        if (!resetConnectionAction.executedAsPlanned()
                || (attempts > 1 && currentMs - lastMsTimestamp > 60000)) {
            LOG.info(
                    "Reset connection as planned: {} in {} attempts",
                    resetConnectionAction.executedAsPlanned(),
                    attempts);
            lastMsTimestamp = System.currentTimeMillis();
        }
        return new ResponseFingerprint(new LinkedList<>(), new LinkedList<>(), SocketState.UP);
    }

    private void sleepFor100ms() {
        try {
            Thread.sleep(100);
        } catch (InterruptedException ex) {
            LOG.error("Sleep interrupted", ex);
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
        return "ResetConnection";
    }

    @Override
    public String toShortString() {
        return "RST";
    }
}
