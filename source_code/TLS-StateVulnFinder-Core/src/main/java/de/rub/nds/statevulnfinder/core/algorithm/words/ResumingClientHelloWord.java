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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class ResumingClientHelloWord extends ClientHelloWord {

    public enum ResumptionType {
        ID,
        TICKET,
        TLS_1_3_TICKET
    }

    private ResumptionType resumptionType;

    public ResumingClientHelloWord() {
        super(CipherSuite.GREASE_00);
    }

    public ResumingClientHelloWord(ResumptionType type) {
        super(TlsWordType.RESUMING_HELLO, CipherSuite.GREASE_00, type == ResumptionType.TICKET);
        resumptionType = type;
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        // resume using most recently negotiated cipher
        cipherSuite = state.getTlsContext().getSelectedCipherSuite();
        adjustConfig(state);
        if (getResumptionType() == ResumptionType.TLS_1_3_TICKET) {
            state.getConfig().setAddPreSharedKeyExtension(true);
            state.getConfig().setAddPSKKeyExchangeModesExtension(true);
        }
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(state.getConfig());
        adjustContext(state);
        if (getResumptionType() == ResumptionType.TICKET
                || getResumptionType() == ResumptionType.TLS_1_3_TICKET) {
            clientHelloMessage.setSessionId(
                    Modifiable.explicit(
                            state.getConfig().getDefaultClientTicketResumptionSessionId()));
        }
        sendMessage(clientHelloMessage, new Record(), state);
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
        ResumingClientHelloWord other = (ResumingClientHelloWord) obj;
        return this.getResumptionType() == other.getResumptionType();
    }

    @Override
    public int hashCode() {
        int hash = 5;
        return hash;
    }

    @Override
    public String toShortString() {
        return resumptionType + "-RCH";
    }

    @Override
    public String toString() {
        return resumptionType + "ResumingClientHello";
    }

    public ResumptionType getResumptionType() {
        return resumptionType;
    }

    public void setResumptionType(ResumptionType resumptionType) {
        this.resumptionType = resumptionType;
    }

    @Override
    public TlsWordType getType() {
        return TlsWordType.RESUMING_HELLO;
    }
}
