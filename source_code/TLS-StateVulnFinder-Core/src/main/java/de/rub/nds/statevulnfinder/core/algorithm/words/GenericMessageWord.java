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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElementRef;
import java.util.Arrays;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author robert
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class GenericMessageWord extends TlsWord {

    private static final Logger LOG = LogManager.getLogger();

    @XmlElementRef private ProtocolMessage message;

    private GenericMessageWord() {}

    public GenericMessageWord(ProtocolMessage message) {
        super(TlsWordType.GENERIC);
        this.message = message;
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        sendMessage(message, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    @Override
    public String toString() {
        return "GenericMessageWord{" + "message=" + message.toCompactString() + '}';
    }

    @Override
    public String toShortString() {
        return message.toShortString();
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + Objects.hashCode(this.message.getClass());
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
        final GenericMessageWord other = (GenericMessageWord) obj;
        return Objects.equals(this.message.getClass(), other.message.getClass());
    }

    public ProtocolMessage getMessage() {
        return message;
    }

    @Override
    public TlsWordType getType() {
        if (message instanceof ApplicationMessage) {
            return TlsWordType.GENERIC_APP_DATA;
        } else if (message instanceof KeyUpdateMessage) {
            return TlsWordType.KEY_UPDATE;
        } else if (message instanceof HeartbeatMessage) {
            return TlsWordType.HEARTBEAT;
        } else if (message instanceof AlertMessage
                && (Arrays.equals(
                                ((AlertMessage) message).getConfig(),
                                new byte[] {
                                    AlertLevel.WARNING.getValue(),
                                    AlertDescription.CLOSE_NOTIFY.getValue()
                                })
                        || ((AlertMessage) message).getDescription().getValue()
                                == AlertDescription.CLOSE_NOTIFY.getValue())) {
            return TlsWordType.CLOSE_NOTIFY;
        } else if (message instanceof CertificateMessage) {
            return TlsWordType.EMPTY_CERTIFICATE;
        } else if (message instanceof ServerHelloDoneMessage) {
            return TlsWordType.SERVER_HELLO_DONE;
        } else if (message instanceof HelloRequestMessage) {
            return TlsWordType.HELLO_REQUEST;
        } else if (message instanceof CertificateVerifyMessage) {
            return TlsWordType.CERTIFICATE_VERIFY;
        } else if (message instanceof EncryptedExtensionsMessage) {
            return TlsWordType.ENCRYPTED_EXTENSIONS;
        }
        return super.getType();
    }
}
