/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.constants;

public enum TlsWordType {
    ANY,
    ANY_APP_DATA,
    GENERIC,
    FINISHED,
    CCS,
    DUMMY_CCS,
    ANY_CCS,
    PADDING_ORACLE,
    BLEICHENBACHER,
    @Deprecated
    HELLO,
    ANY_CLIENT_HELLO,
    TLS12_CLIENT_HELLO,
    TLS13_CLIENT_HELLO,
    KEY_UPDATE,
    HELLO_RETRY_REQUEST,
    RESET_CONNECTION,
    CLIENT_KEY_EXCHANGE,
    RESUMING_HELLO,
    HRR_ENFORCING_HELLO,
    EMPTY_CERTIFICATE,
    HTTPS_REQUEST,
    HTTPS_RESPONSE,
    NEW_SESSION_TICKET,
    GENERIC_APP_DATA,
    HEARTBEAT,
    CLOSE_NOTIFY,
    TLS12_SERVER_HELLO,
    TLS13_SERVER_HELLO,
    ANY_SERVER_HELLO,
    CERTIFICATE,
    SERVER_KEY_EXCHANGE,
    SERVER_HELLO_DONE,
    HELLO_REQUEST,
    CERTIFICATE_REQUEST,
    ENCRYPTED_EXTENSIONS,
    CERTIFICATE_VERIFY,
    // this type must never appear in any chain
    ARTIFICIAL_DEAD_END;

    public boolean isAnyClientHello() {
        switch (this) {
            case ANY_CLIENT_HELLO:
            case TLS12_CLIENT_HELLO:
            case TLS13_CLIENT_HELLO:
            case HRR_ENFORCING_HELLO:
            case RESUMING_HELLO:
                return true;
            default:
                return false;
        }
    }

    public boolean isAnyServerHello() {
        switch (this) {
            case TLS12_SERVER_HELLO:
            case TLS13_SERVER_HELLO:
                return true;
            default:
                return false;
        }
    }

    public boolean isCCS() {
        return this == TlsWordType.CCS || this == TlsWordType.DUMMY_CCS;
    }

    /**
     * Checks if a given Type is a regular, i.e non-resuming, Client Hello
     *
     * @return true if non resuming ClientHello
     */
    public boolean isRegularClientHello() {
        return this == TlsWordType.TLS12_CLIENT_HELLO || this == TlsWordType.TLS13_CLIENT_HELLO;
    }

    /**
     * Checks if a given Type is a regular, i.e non-resuming, Server Hello
     *
     * @return true if non resuming ServerHello
     */
    public boolean isRegularServerHello() {
        return this == TlsWordType.TLS12_SERVER_HELLO || this == TlsWordType.TLS13_SERVER_HELLO;
    }

    public boolean isAppData() {
        return this == TlsWordType.GENERIC_APP_DATA
                || this == TlsWordType.HTTPS_REQUEST
                || this == TlsWordType.HTTPS_RESPONSE;
    }

    public static boolean effectivelyEquals(TlsWordType first, TlsWordType other) {
        if (first == other) {
            return true;
        }

        if (first == TlsWordType.ANY || other == TlsWordType.ANY) {
            return true;
        }

        if (first == null || other == null) {
            return false;
        }

        if (first == TlsWordType.ANY_APP_DATA || other == TlsWordType.ANY_APP_DATA) {
            TlsWordType specificType = (first == TlsWordType.ANY_APP_DATA ? other : first);
            return specificType.isAppData();
        } else if (first == TlsWordType.ANY_CLIENT_HELLO || other == TlsWordType.ANY_CLIENT_HELLO) {
            TlsWordType specificType = (first == TlsWordType.ANY_CLIENT_HELLO ? other : first);
            return specificType.isAnyClientHello();
        } else if (first == TlsWordType.ANY_CCS || other == TlsWordType.ANY_CCS) {
            TlsWordType specificType = (first == TlsWordType.ANY_CCS ? other : first);
            return specificType.isCCS();
        } else if (first == TlsWordType.ANY_SERVER_HELLO || other == TlsWordType.ANY_SERVER_HELLO) {
            TlsWordType specificType = (first == TlsWordType.ANY_SERVER_HELLO ? other : first);
            return specificType.isAnyServerHello();
        }
        return false;
    }
}
