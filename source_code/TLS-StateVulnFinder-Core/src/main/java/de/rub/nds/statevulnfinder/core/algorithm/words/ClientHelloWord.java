/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author robert
 */
public class ClientHelloWord extends HelloWord {

    private static final Logger LOG = LogManager.getLogger();

    private boolean includeSessionTicketExtension;

    public ClientHelloWord() {}

    public ClientHelloWord(CipherSuite cipherSuite) {
        super(cipherSuite);
        this.includeSessionTicketExtension = false;
    }

    public ClientHelloWord(CipherSuite cipherSuite, boolean includeSessionTicketExtension) {
        super(cipherSuite);
        this.includeSessionTicketExtension = includeSessionTicketExtension;
    }

    public ClientHelloWord(
            TlsWordType explicitType,
            CipherSuite cipherSuite,
            boolean includeSessionTicketExtension) {
        super(explicitType, cipherSuite);
        this.includeSessionTicketExtension = includeSessionTicketExtension;
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        LOG.debug("Sending:CH:" + cipherSuite.name());
        adjustConfig(state);
        ClientHelloMessage clientHelloMessage = getHelloMessage(state);
        adjustContext(state);
        ensureSoleKeyShareGroupIsHrrGroup(state, clientHelloMessage);
        ensureClientRandomIsRetainedAfterHrr(state, clientHelloMessage);
        sendMessage(clientHelloMessage, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    protected ClientHelloMessage getHelloMessage(State state) {
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(state.getConfig());
        clientHelloMessage.setSessionId(Modifiable.explicit(new byte[0]));

        SessionTicketTLSExtensionMessage sessionTicketExtension =
                clientHelloMessage.getExtension(SessionTicketTLSExtensionMessage.class);
        if (sessionTicketExtension != null) {
            byte[] extensionType = ExtensionType.SESSION_TICKET.getValue();
            byte[] length = new byte[ExtensionByteLength.EXTENSIONS_LENGTH];
            sessionTicketExtension.setExtensionBytes(
                    Modifiable.explicit(ArrayConverter.concatenate(extensionType, length)));
        }
        return clientHelloMessage;
    }

    protected void adjustContext(State state) {
        // do not reset digest in TLS 1.3 to handle HRRs correctly
        if (!cipherSuite.isTLS13()) {
            // enable renegotation
            TlsContext tlsContext = state.getTlsContext();
            tlsContext.getDigest().reset();
        }
    }

    protected void adjustConfig(State state) {
        state.getConfig().setDefaultSelectedCipherSuite(cipherSuite);
        state.getConfig().setDefaultServerSupportedCipherSuites(cipherSuite);
        state.getConfig().setDefaultClientSupportedCipherSuites(cipherSuite);
        if (cipherSuite.name().contains("EC") || cipherSuite.isTLS13()) {
            state.getConfig().setAddECPointFormatExtension(true);
            state.getConfig().setAddEllipticCurveExtension(true);
        } else {
            state.getConfig().setAddECPointFormatExtension(false);
            state.getConfig().setAddEllipticCurveExtension(false);
        }

        if (cipherSuite.isTLS13()) {
            state.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS13);
            state.getConfig().setAddSupportedVersionsExtension(true);
            state.getConfig().setAddKeyShareExtension(true);
            state.getConfig().setAddSessionTicketTLSExtension(false);
            state.getConfig().setAddPreSharedKeyExtension(false);
            if (state.getTlsContext().getExtensionCookie() != null
                    && digestIndicatesHelloRetryRequestFlow(state)) {
                state.getConfig().setAddCookieExtension(true);
            } else {
                state.getConfig().setAddCookieExtension(false);
            }
        } else {
            state.getConfig().setAddSupportedVersionsExtension(false);
            state.getConfig().setAddKeyShareExtension(false);
            state.getConfig().setAddPSKKeyExchangeModesExtension(false);
            state.getConfig().setAddSessionTicketTLSExtension(isIncludeSessionTicketExtension());
            state.getConfig().setAddPreSharedKeyExtension(false);
            state.getConfig().setAddCookieExtension(false);
        }

        // GnuTls adaptation:
        state.getConfig().setAddHeartbeatExtension(true);
    }

    @Override
    public String getHelloType() {
        if (!cipherSuite.isTLS13()) {
            if (isIncludeSessionTicketExtension()) {
                return "T-Client";
            }
            return "ID-Client";
        }
        return "Client";
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
        final ClientHelloWord other = (ClientHelloWord) obj;
        return this.cipherSuite == other.cipherSuite
                && (cipherSuite.isTLS13()
                        || this.isIncludeSessionTicketExtension()
                                == other.isIncludeSessionTicketExtension());
    }

    public boolean isIncludeSessionTicketExtension() {
        return includeSessionTicketExtension;
    }

    public void setIncludeSessionTicketExtension(boolean includeSessionTicketExtension) {
        this.includeSessionTicketExtension = includeSessionTicketExtension;
    }

    private void ensureSoleKeyShareGroupIsHrrGroup(State state, ClientHelloMessage clientHello) {
        NamedGroup selectedGroup = state.getTlsContext().getSelectedGroup();
        ProtocolVersion selectedVersion = state.getTlsContext().getSelectedProtocolVersion();
        boolean digestIndicatesHrr = digestIndicatesHelloRetryRequestFlow(state);
        if (digestIndicatesHrr
                && selectedVersion == ProtocolVersion.TLS13
                && selectedGroup != null
                && selectedGroup.isTls13()
                && !state.getTlsContext()
                        .getConfig()
                        .getDefaultClientKeyShareNamedGroups()
                        .contains(selectedGroup)) {
            KeyShareExtensionMessage keyShareExtension =
                    clientHello.getExtension(KeyShareExtensionMessage.class);
            keyShareExtension.getKeyShareList().clear();
            keyShareExtension
                    .getKeyShareList()
                    .add(new KeyShareEntry(selectedGroup, state.getConfig().getKeySharePrivate()));
        }
    }

    private void ensureClientRandomIsRetainedAfterHrr(State state, ClientHelloMessage clientHello) {
        if (digestIndicatesHelloRetryRequestFlow(state)
                && state.getTlsContext().getClientRandom() != null) {
            clientHello.setRandom(Modifiable.explicit(state.getTlsContext().getClientRandom()));
        }
    }

    private boolean digestIndicatesHelloRetryRequestFlow(State state) {
        return state.getTlsContext().getDigest().getRawBytes().length > 0
                && state.getTlsContext().getDigest().getRawBytes()[0]
                        == HandshakeMessageType.MESSAGE_HASH.getValue();
    }

    @Override
    public TlsWordType getType() {
        if (cipherSuite.isTLS13()) {
            return TlsWordType.TLS13_CLIENT_HELLO;
        } else {
            return TlsWordType.TLS12_CLIENT_HELLO;
        }
    }
}
