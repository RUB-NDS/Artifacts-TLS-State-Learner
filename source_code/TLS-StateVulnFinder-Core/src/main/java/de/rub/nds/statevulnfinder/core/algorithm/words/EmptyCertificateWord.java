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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class EmptyCertificateWord extends TlsWord {

    public EmptyCertificateWord() {
        super(TlsWordType.EMPTY_CERTIFICATE);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        CertificateMessage emptyCert = new CertificateMessage();
        emptyCert.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
        sendMessage(emptyCert, new Record(), state);
        return receiveMessages(state, receiveHint);
    }
}
