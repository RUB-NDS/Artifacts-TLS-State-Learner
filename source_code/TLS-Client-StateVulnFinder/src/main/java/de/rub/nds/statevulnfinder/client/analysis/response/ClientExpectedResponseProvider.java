/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.analysis.response;

import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponse;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponseProvider;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;

public class ClientExpectedResponseProvider extends ExpectedResponseProvider {

    @Override
    public ExpectedResponse[] getExpectedTls12Responses() {
        ExpectedResponse expectedAppDataResponse = new ExpectedResponse(TlsWordType.ANY_APP_DATA);
        expectedAppDataResponse.setIgnorableTypes(TlsWordType.ANY_APP_DATA);
        return new ExpectedResponse[] {
            new ExpectedResponse(TlsWordType.TLS12_SERVER_HELLO),
            new ExpectedResponse(TlsWordType.CERTIFICATE),
            new ExpectedResponse(TlsWordType.SERVER_KEY_EXCHANGE),
            new ExpectedResponse(
                    TlsWordType.SERVER_HELLO_DONE,
                    ClientKeyExchangeMessage.class,
                    ChangeCipherSpecMessage.class,
                    FinishedMessage.class),
            new ExpectedResponse(TlsWordType.HELLO_REQUEST, ClientHelloMessage.class),
            // allow empty response if ignored
            new ExpectedResponse(TlsWordType.HELLO_REQUEST, ContextProperty.HANDSHAKE_UNFINISHED),
            new ExpectedResponse(TlsWordType.ANY_CCS),
            new ExpectedResponse(TlsWordType.FINISHED),
            new ExpectedResponse(TlsWordType.CERTIFICATE_REQUEST),
            expectedAppDataResponse
        };
    }

    @Override
    public ExpectedResponse[] getExpectedTls13Responses() {
        ExpectedResponse expectedAppDataResponse = new ExpectedResponse(TlsWordType.ANY_APP_DATA);
        expectedAppDataResponse.setIgnorableTypes(TlsWordType.ANY_APP_DATA);
        return new ExpectedResponse[] {
            new ExpectedResponse(TlsWordType.TLS13_SERVER_HELLO),
            new ExpectedResponse(TlsWordType.ENCRYPTED_EXTENSIONS),
            new ExpectedResponse(TlsWordType.CERTIFICATE),
            new ExpectedResponse(TlsWordType.CERTIFICATE_VERIFY),
            new ExpectedResponse(
                    TlsWordType.FINISHED, ChangeCipherSpecMessage.class, FinishedMessage.class),
            new ExpectedResponse(TlsWordType.FINISHED, FinishedMessage.class),
            new ExpectedResponse(TlsWordType.NEW_SESSION_TICKET),
            new ExpectedResponse(TlsWordType.KEY_UPDATE, KeyUpdateMessage.class),
            // may be empty if not supported
            new ExpectedResponse(TlsWordType.KEY_UPDATE),
            new ExpectedResponse(TlsWordType.HELLO_RETRY_REQUEST, ClientHelloMessage.class),
            new ExpectedResponse(
                    TlsWordType.HELLO_RETRY_REQUEST,
                    ChangeCipherSpecMessage.class,
                    ClientHelloMessage.class),
            new ExpectedResponse(TlsWordType.ANY_CCS),
            // if the library allows the HR after sending SH, it must not send a CH
            new ExpectedResponse(TlsWordType.HELLO_REQUEST),
            expectedAppDataResponse
        };
    }
}
