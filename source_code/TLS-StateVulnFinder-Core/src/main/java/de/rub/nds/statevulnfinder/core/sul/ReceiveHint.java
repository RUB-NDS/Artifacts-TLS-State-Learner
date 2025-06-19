/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.List;

public class ReceiveHint {

    private final List<ProtocolMessage> expectedMessages;
    private final SocketState socketState;

    public ReceiveHint(List<ProtocolMessage> expectedMessages) {
        this.expectedMessages = expectedMessages;
        this.socketState = SocketState.UP;
    }

    public ReceiveHint(List<ProtocolMessage> expectedMessages, SocketState socketState) {
        this.expectedMessages = expectedMessages;
        this.socketState = socketState;
    }

    public boolean hasExpectation() {
        return getExpectedMessages() != null && getSocketState() != null;
    }

    public List<ProtocolMessage> getExpectedMessages() {
        return expectedMessages;
    }

    public SocketState getSocketState() {
        return socketState;
    }
}
