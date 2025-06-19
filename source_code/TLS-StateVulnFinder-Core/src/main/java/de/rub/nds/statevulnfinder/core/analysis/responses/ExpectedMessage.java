/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.responses;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;

public class ExpectedMessage {
    private final Class<? extends ProtocolMessage> message;
    private final boolean required;
    private final boolean multipleAllowed;

    public ExpectedMessage(Class<? extends ProtocolMessage> message) {
        this.message = message;
        required = true;
        multipleAllowed = false;
    }

    public ExpectedMessage(Class<? extends ProtocolMessage> message, boolean required) {
        this.message = message;
        this.required = required;
        multipleAllowed = false;
    }

    public ExpectedMessage(
            Class<? extends ProtocolMessage> message, boolean required, boolean multipleAllowed) {
        this.message = message;
        this.required = required;
        this.multipleAllowed = multipleAllowed;
    }

    public Class<? extends ProtocolMessage> getMessage() {
        return message;
    }

    public boolean isRequired() {
        return required;
    }

    public boolean isMultipleAllowed() {
        return multipleAllowed;
    }
}
