/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import de.rub.nds.tlsscanner.core.probe.padding.vector.VeryShortPaddingGenerator;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * @author robert
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class PaddingOracleWord extends TlsWord {

    private String identifier;
    private ProtocolMessageType protocolMessageType;
    private static Map<CipherSuite, Map<String, PaddingVector>> cipherVectorMap = new HashMap<>();

    private PaddingOracleWord() {}

    public PaddingOracleWord(String identifier, ProtocolMessageType protocolMessageType) {
        super(TlsWordType.PADDING_ORACLE);
        this.identifier = identifier;
        this.protocolMessageType = protocolMessageType;
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        PaddingVector ciphersuitePaddingVector = getVectorForCipher(state);
        Record record = ciphersuitePaddingVector.createRecord();
        record.setContentType(Modifiable.explicit(getProtocolMessageType().getValue()));
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setCleanProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        sendMessage(new ApplicationMessage(), record, state);
        return receiveMessages(state, receiveHint);
    }

    private PaddingVector getVectorForCipher(State state) {
        // use cipher from encryptor instead of context to reflect actual active
        // cipher in renegotiation
        CipherSuite activeCipher =
                state.getTlsContext()
                        .getRecordLayer()
                        .getEncryptorCipher()
                        .getState()
                        .getCipherSuite();

        if (!cipherVectorMap.containsKey(activeCipher)) {
            List<PaddingVector> paddingRecords =
                    new VeryShortPaddingGenerator().getVectors(activeCipher, ProtocolVersion.TLS12);
            Map<String, PaddingVector> vectorRecordMap = new HashMap<>();
            paddingRecords.forEach(vector -> vectorRecordMap.put(vector.getIdentifier(), vector));
            getCipherVectorMap().put(activeCipher, vectorRecordMap);
        }

        return getCipherVectorMap().get(activeCipher).get(getIdentifier());
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.getProtocolMessageType());
        return hash;
    }

    @Override
    public String toShortString() {
        return "PO_" + getProtocolMessageType();
    }

    @Override
    public String toString() {
        return "Padding Oracle{type=" + getProtocolMessageType() + ", " + identifier + "}";
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
        final PaddingOracleWord other = (PaddingOracleWord) obj;
        if (!this.getIdentifier().equals(other.getIdentifier())) {
            return false;
        }
        if (this.getProtocolMessageType() != other.getProtocolMessageType()) {
            return false;
        }
        return true;
    }

    public ProtocolMessageType getProtocolMessageType() {
        return this.protocolMessageType;
    }

    public void setProtocolMessageType(ProtocolMessageType protocolMessageType) {
        this.protocolMessageType = protocolMessageType;
    }

    public static Map<CipherSuite, Map<String, PaddingVector>> getCipherVectorMap() {
        return cipherVectorMap;
    }

    public static void setCipherVectorMap(
            Map<CipherSuite, Map<String, PaddingVector>> aCipherVectorMap) {
        cipherVectorMap = aCipherVectorMap;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }
}
