/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

public enum InterestingProperty {
    FATAL_ALERT_DOES_NOT_GO_TO_ERROR,
    UNKNOWN_ALERT_DESCRIPTION,
    MULTIPLE_ALERTS,
    PARTIAL_HANDSHAKE_MESSAGES_RECEIVED,
    HAS_UNNAMED_TERMINAL_STATES,
    HANDSHAKE_RECEIVED_TO_TERMINAL_STATES,
    HANDSHAKE_RECEIVED_TO_ERROR_STATE,
    DECRYPTION_RELATED_ALERT_WITHOUT_CCS,
    RESPONSE_HAS_RECORD_BUT_NO_MESSAGE;
}
