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
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloWord extends HelloWord {

    private static final Logger LOG = LogManager.getLogger();

    public ServerHelloWord() {}

    public ServerHelloWord(CipherSuite cipherSuite) {
        super(cipherSuite);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        LOG.debug("Sending:SH:" + cipherSuite.name());
        state.getConfig().setDefaultSelectedCipherSuite(cipherSuite);
        state.getConfig().setDefaultServerSupportedCipherSuites(cipherSuite);
        state.getConfig().setDefaultClientSupportedCipherSuites(cipherSuite);

        // TODO adapt to analyzed ClientHello
        state.getConfig().setAddRenegotiationInfoExtension(false);
        state.getConfig().setAddHeartbeatExtension(false);
        state.getConfig().setAddServerNameIndicationExtension(false);

        if (cipherSuite.isTLS13()) {
            state.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS13);
            state.getConfig().setAddSupportedVersionsExtension(true);
            state.getConfig().setAddKeyShareExtension(true);
            state.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP256R1);
        }

        ServerHelloMessage serverHello = new ServerHelloMessage(state.getConfig());
        if (state.getTlsContext().getConnection().getLocalConnectionEndType()
                == ConnectionEndType.CLIENT) {
            serverHello.setAdjustContext(Modifiable.explicit(false));
        }
        sendMessage(serverHello, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    @Override
    public String getHelloType() {
        return "Server";
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + Objects.hashCode(this.cipherSuite);
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
        final ServerHelloWord other = (ServerHelloWord) obj;
        return this.cipherSuite == other.cipherSuite;
    }

    @Override
    public TlsWordType getType() {
        if (cipherSuite.isTLS13()) {
            return TlsWordType.TLS13_SERVER_HELLO;
        } else {
            return TlsWordType.TLS12_SERVER_HELLO;
        }
    }
}
