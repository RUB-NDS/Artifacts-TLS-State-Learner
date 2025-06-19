/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HRREnforcingClientHelloWord extends ClientHelloWord {

    private static final Logger LOG = LogManager.getLogger();

    private HRREnforcingClientHelloWord() {}

    public HRREnforcingClientHelloWord(CipherSuite cipherSuite) {
        super(TlsWordType.HRR_ENFORCING_HELLO, cipherSuite, false);
        if (!cipherSuite.isTLS13()) {
            throw new IllegalArgumentException(
                    cipherSuite
                            + " must not be used for HRREnforcingClientHelloWord as it is not a TLS 1.3 cipher suite");
        }
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        LOG.debug("Sending:CH to enforce HRR:" + cipherSuite.name());
        adjustConfig(state);
        ClientHelloMessage clientHelloMessage = getHelloMessage(state);
        // leave extension empty to enforce HRR
        KeyShareExtensionMessage keyShareExtension =
                clientHelloMessage.getExtension(KeyShareExtensionMessage.class);
        keyShareExtension.setKeyShareListBytes(Modifiable.explicit(new byte[0]));
        adjustContext(state);
        sendMessage(clientHelloMessage, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    @Override
    public String toShortString() {
        return "HRREnforcingClientHello";
    }

    @Override
    public String toString() {
        // output should be distinct from java-default ClientHello toString
        if (VulnerabilityFinderConfig.SIMPLE_CIPHER_SUITE_EXPORT_MODE) {
            return "HRREnforcingClientHello{TLS13}";
        }
        return "HRREnforcingClientHello{suite=" + cipherSuite + "}";
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
        final HRREnforcingClientHelloWord other = (HRREnforcingClientHelloWord) obj;
        return this.cipherSuite == other.cipherSuite;
    }

    // todo: rework type system
    @Override
    public TlsWordType getType() {
        return TlsWordType.HRR_ENFORCING_HELLO;
    }
}
