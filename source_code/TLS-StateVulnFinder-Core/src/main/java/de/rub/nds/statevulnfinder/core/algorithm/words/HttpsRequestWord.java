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
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** An HTTPS request. Not a GenericMessageWord since the final Config is required */
public class HttpsRequestWord extends TlsWord {

    private static final Logger LOG = LogManager.getLogger();

    private static final String HTTP_REQUEST_SUFFIX =
            "\r\n"
                    + //
                    "Sec-Ch-Ua: \"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"\r\n"
                    + //
                    "Sec-Ch-Ua-Mobile: ?0\r\n"
                    + //
                    "Sec-Ch-Ua-Platform: \"macOS\"\r\n"
                    + //
                    "Accept-Language: en-GB\r\n"
                    + //
                    "Upgrade-Insecure-Requests: 1\r\n"
                    + //
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36\r\n"
                    + //
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
                    + //
                    "Sec-Fetch-Site: none\r\n"
                    + //
                    "Sec-Fetch-Mode: navigate\r\n"
                    + //
                    "Sec-Fetch-User: ?1\r\n"
                    + //
                    "Sec-Fetch-Dest: document\r\n"
                    + //
                    "Accept-Encoding: gzip, deflate, br\r\n"
                    + //
                    "Priority: u=0, i\r\n"
                    + //
                    "Connection: keep-alive\r\n"
                    + "\r\n";
    private static final String HTTP_REQUEST_PREFIX =
            "GET / HTTP/1.1\r\n"
                    + //
                    "Host: ";

    public HttpsRequestWord() {
        super(TlsWordType.HTTPS_REQUEST);
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        String hostname = state.getConfig().getDefaultClientConnection().getHostname();
        if (hostname == null) {
            hostname = "";
        }
        String httpRequest = HTTP_REQUEST_PREFIX + hostname + HTTP_REQUEST_SUFFIX;
        byte[] encodedRequest = httpRequest.getBytes();
        ApplicationMessage appData = new ApplicationMessage(encodedRequest);
        // HttpRequestMessage httpsRequest = new HttpRequestMessage(state.getConfig());
        sendMessage(appData, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    @Override
    public String toString() {
        return "HTTPSRequest";
    }

    @Override
    public String toShortString() {
        return "HTTPS";
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

        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        return hash;
    }
}
