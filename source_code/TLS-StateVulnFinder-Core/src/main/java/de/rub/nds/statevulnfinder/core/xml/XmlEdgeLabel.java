/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.xml;

import de.rub.nds.statevulnfinder.core.algorithm.responses.UndecryptedAlertsCompoundMessage;
import de.rub.nds.statevulnfinder.core.algorithm.words.*;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import jakarta.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class XmlEdgeLabel {

    @XmlElements(
            value = {
                @XmlElement(type = BleichenbacherWord.class, name = "BleichenbacherWord"),
                @XmlElement(type = ChangeCipherSpecWord.class, name = "ChangeCipherSpecWord"),
                @XmlElement(type = EmptyCertificateWord.class, name = "EmptyCertificateWord"),
                @XmlElement(type = ResumingClientHelloWord.class, name = "ResumingClientHelloWord"),
                @XmlElement(
                        type = HRREnforcingClientHelloWord.class,
                        name = "HRREnforcingClientHelloWord"),
                @XmlElement(type = ClientKeyExchangeWord.class, name = "ClientKeyExchangeWord"),
                @XmlElement(type = HttpsRequestWord.class, name = "HttpsRequestWord"),
                @XmlElement(type = ResetConnectionWord.class, name = "ResetConnectionWord"),
                @XmlElement(type = ClientHelloWord.class, name = "ClientHelloWord"),
                @XmlElement(type = FinishedWord.class, name = "FinishedWord"),
                @XmlElement(type = GenericMessageWord.class, name = "GenericMessageWord"),
                @XmlElement(type = HelloRetryRequestWord.class, name = "HelloRetryRequestWord"),
                @XmlElement(type = PaddingOracleWord.class, name = "PaddingOracleWord"),
                @XmlElement(type = ServerHelloWord.class, name = "ServerHelloWord"),
                @XmlElement(
                        type = DummyChangeCipherSpecWord.class,
                        name = "DummyChangeCipherSpecWord"),
                @XmlElement(type = ServerKeyExchangeWord.class, name = "ServerKeyExchangeWord"),
                @XmlElement(
                        type = UndecryptedAlertsCompoundMessage.class,
                        name = "UndecryptedAlertsCompoundMessage")
            })
    private TlsWord input;

    @XmlElement private SulResponse output;

    public XmlEdgeLabel() {}

    public XmlEdgeLabel(TlsWord input, SulResponse output) {
        this.input = input;
        this.output = output;
    }

    public TlsWord getInput() {
        return input;
    }

    public void setInput(TlsWord input) {
        this.input = input;
    }

    public SulResponse getOutput() {
        return output;
    }

    public void setOutput(SulResponse output) {
        this.output = output;
    }
}
