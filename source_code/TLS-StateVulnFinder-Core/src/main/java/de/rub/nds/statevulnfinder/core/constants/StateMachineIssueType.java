/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.constants;

public enum StateMachineIssueType {
    NO_HAPPY_FLOW,
    CRITICAL_MESSAGE_OUT_OF_ORDER,
    LEAVING_HAPPY_FLOW,
    STATE_CONFUSION,
    UNWANTED_HAPPY_FLOW,
    BLEICHENBACHER,
    PADDING_ORACLE,
    KEYBLOCK_LEAK,
    CYCLE,
    INTERNAL_ERROR,
    DIVERGING_CCS,
    UNEXPECTED_RESPONSE,
    ODD_ERROR_STATE_TRANSITION,
    NO_FAIL_FAST,
    UNKNOWN_MESSAGE,
    REDUNDANT_STATE
}
