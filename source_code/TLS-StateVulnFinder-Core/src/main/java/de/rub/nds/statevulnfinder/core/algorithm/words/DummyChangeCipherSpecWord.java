/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class DummyChangeCipherSpecWord extends TlsWord {
    public DummyChangeCipherSpecWord() {
        super(TlsWordType.DUMMY_CCS);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        ChangeCipherSpecMessage dummyCcs = new ChangeCipherSpecMessage();
        dummyCcs.setAdjustContext(Modifiable.explicit(false));
        sendMessage(dummyCcs, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    @Override
    public String toString() {
        return "DummyChangeCipherSpecWord{" + '}';
    }

    @Override
    public String toShortString() {
        return "DummyCCS";
    }

    @Override
    public int hashCode() {
        int hash = 3;
        return hash;
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
}
