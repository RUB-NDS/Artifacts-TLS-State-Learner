/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

public enum CommonIssue {
    IGNORES_CCS_AFTER_FIN, // CCS | <empty> leads to terminal state, DummyCCS | <empty> loops state.
    // The terminal state is caused by us using wrong keys subsequently.
    INTERNAL_ERROR_AFTER_DUMMY_CCS, // Only in happy flow path when sent instead of 'real' CCS
    REJECTS_HTTPS, // In FIN State.
    ILLEGAL_PARAMETER_UPON_CH_AFTER_HRR_ENFORCING_CH, // This was an issue on our end - we sent the
    // second CH with a different client random
    POST_HANDSHAKE_CCS_TO_DUMMY_CCS_STATE, // These servers allow a transition into a terminal
    // state. All subsequent messages lead to a closed
    // connection seemingly(?) without alert. This may be more interesting than
    // IGNORES_CCS_AFTER_FIN but only if dummy ccs causes a state change, too
    MULTIPLE_CHS_ALLOWED_HANDSHAKE, // Some hosts accept multiple CHs before and after the fin and
    // each time
    // reply with server handshake flight. It seems to be limited to 3
    // attempts, though.
    MULTIPLE_CHS_ALLOWED_RENEGOTIATION, // see above
    MULTIPLE_CHS_ALLOWED_AND_CAN_COMPLETE_HANDSHAKE_WITH_PARTIAL_TRANSCRIPT, // see above
    MULTIPLE_CHS_ALLOWED_BUT_UNABLE_TO_COMPLETE_WITH_PARIAL_TRANSCRIPT,
    STARTING_WITH_DUMMY_CCS_LEADS_TO_TERMINAL_EXCLUSIVELY, // Maybe interesting - apparently, the
    // peer accepts a
    // CCS but subsequently rejects handshake messages. Btw a good reason to keep the Dummy CCS in
    // the alphabet
    STARTING_WITH_VARIOUS_GENERIC_INPUTS_LEADS_TO_TERMINAL, // usually seen for EndOfEarlyData and
    // similar sent at the start
    ALONG_DUMMY_CCS_OTHER_INITAL_INPUTS_TO_TERMINAL, // see above but for other inputs that also
    // lead to this terminal state
    HTTPS_IGNORED_DURING_HANDSHAKE_BUT_NOT_AS_FIRST, // only when no response has been received -
    // maybe interesting
    // but unlikely
    TLS_13_KEY_UPDATE_TO_ERROR_STATE, // can't handle key update, goes to error without message
    CLOSE_NOTIFY_IGNORED, // close notify does not lead to error state
    DUPLICATE_DUMMY_STATE_NOT_CONSIDERED_ERROR_STATE_BUG, // We only track one dummy state, however,
    // due to the majority vote cache filter
    // rules have not always been applied
    // resulting in duplicated dummy states
    // where only one or very few inputs do
    // not yield an InvalidLearnerTransition
    FIN_STATE_NAME_CONFUSION_BUG, // Related to dummy state issue
    IGNORES_CCS_AFTER_HANDSHAKE_TLS13, // No state changes, simply ignores the input as most
    // implementations do during the handshake (during the
    // handshake is RFC compliant, after the handshake the client
    // shouldn't be able to send it)
    POST_HANDSHAKE_CCS_TO_DUMMY_CCS_STATE_BUT_IGNORES_DUMMY_CCS, // Not sure if this ever not occurs
    // but just in case, we track it
    // explicitly
    MULTIPLE_CHS_REJECTED_WITH_ILLEGAL_PARAMETER,
    MULTIPLE_CHS_REJECTED_WITH_HANDSHAKE_FAILURE,
    MULTIPLE_CHS_REJECTED_WITH_CLOSE_NOTIFY,
    MULTIPLE_CHS_REJECTED_NO_RECORD_SOCKET_EXCEPTION,
    REJECTED_OUR_CERT, // We used a generic self-signed certificate
    ACCEPTS_RENEGOTIATION_BUT_CLOSES_CONNECTION_WITH_SH_FLIGHT, // We get SH CRT SKE SHD but also
    // TCP FIN. Mixed signals :/
    ASSUMED_CACHE_FILTER_ORACLE_BUG, // differences introduced by the lacking cache filter for
    // majority votes, this type separates the real padding oracle
    // findings from spurious ones
    ACCEPTS_RENEGOTIATION_BUT_CLOSES_CONNECTION_WITH_SH_FLIGHT_RESUMPTION, // same as above but
    // resumption was
    // accepted in reneg
    ACCEPTS_UNSOLICITATED_CERTIFICATE, // No CertReq but Cert, CKE, CCS, FIN conclude the handshake
    REJECTED_3DES_CH_WITH_HANDSHAKE_FAILURE;
}
