/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.responses;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "UndecryptedAlertsCompound")
public class UndecryptedAlertsCompoundMessage extends ProtocolMessage {

    public UndecryptedAlertsCompoundMessage() {
        protocolMessageType = ProtocolMessageType.ALERT;
    }

    public UndecryptedAlertsCompoundMessage(List<AlertMessage> alertsToMerge) {
        protocolMessageType = ProtocolMessageType.ALERT;
        ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();
        for (AlertMessage alert : alertsToMerge) {
            byteOutStream.writeBytes(alert.getCompleteResultingMessage().getValue());
        }
        setCompleteResultingMessage(byteOutStream.toByteArray());
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext tlsContext) {
        throw new UnsupportedOperationException("Unimplemented method 'getHandler'");
    }

    @Override
    public ProtocolMessageSerializer getSerializer(TlsContext tlsContext) {
        throw new UnsupportedOperationException("Unimplemented method 'getSerializer'");
    }

    @Override
    public ProtocolMessagePreparator getPreparator(TlsContext tlsContext) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPreparator'");
    }

    @Override
    public ProtocolMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getParser'");
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof UndecryptedAlertsCompoundMessage && other != null) {
            return true;
        }
        return false;
    }

    @Override
    public String toShortString() {
        return "Undecrypted-Alerts";
    }

    @Override
    public String toCompactString() {
        return "UndecryptedAlertsCompound";
    }
}
