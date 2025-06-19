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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.util.Objects;

@XmlAccessorType(XmlAccessType.FIELD)
public class HelloRetryRequestWord extends TlsWord {
    private NamedGroup requestedGroup;
    private CipherSuite requestedCipher;

    private HelloRetryRequestWord() {}

    public HelloRetryRequestWord(NamedGroup requestedGroup, CipherSuite requestedCipher) {
        super(TlsWordType.HELLO_RETRY_REQUEST);
        this.requestedGroup = requestedGroup;
        this.requestedCipher = requestedCipher;
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        state.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS13);
        state.getConfig().setAddSupportedVersionsExtension(true);
        state.getConfig().setAddKeyShareExtension(true);
        state.getConfig().setAddRenegotiationInfoExtension(false);
        state.getConfig().setAddHeartbeatExtension(false);
        state.getConfig().setAddServerNameIndicationExtension(false);

        state.getConfig().setDefaultSelectedCipherSuite(getRequestedCipher());
        state.getConfig().setDefaultServerSupportedCipherSuites(getRequestedCipher());
        state.getConfig().setDefaultClientSupportedCipherSuites(getRequestedCipher());

        state.getConfig().setDefaultSelectedNamedGroup(getRequestedGroup());
        state.getConfig().setDefaultServerNamedGroups(getRequestedGroup());

        ServerHelloMessage serverHello = new ServerHelloMessage(state.getConfig());
        serverHello.setRandom(Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));

        if (state.getTlsContext().getConnection().getLocalConnectionEndType()
                == ConnectionEndType.CLIENT) {
            serverHello.setAdjustContext(Modifiable.explicit(false));
        }
        sendMessage(serverHello, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    public NamedGroup getRequestedGroup() {
        return requestedGroup;
    }

    public CipherSuite getRequestedCipher() {
        return requestedCipher;
    }

    @Override
    public String toString() {
        return "HelloRetryRequest";
    }

    @Override
    public String toShortString() {
        return "HelloRetryRequest";
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
        final HelloRetryRequestWord other = (HelloRetryRequestWord) obj;
        return this.requestedCipher == other.getRequestedCipher()
                && this.requestedGroup == other.getRequestedGroup();
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 37 * hash + Objects.hashCode(this.requestedGroup);
        hash = 37 * hash + Objects.hashCode(this.requestedCipher);
        return hash;
    }
}
