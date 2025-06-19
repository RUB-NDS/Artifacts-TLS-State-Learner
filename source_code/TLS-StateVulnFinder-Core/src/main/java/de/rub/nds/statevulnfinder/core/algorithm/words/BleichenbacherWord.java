/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherScanType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1Vector;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1VectorGenerator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class BleichenbacherWord extends TlsWord {

    private static final Logger LOG = LogManager.getLogger(BleichenbacherWord.class.getName());

    @XmlJavaTypeAdapter(Pkcs1VectorAdapter.class)
    private Pkcs1Vector vector;

    private BleichenbacherWord() {}

    public BleichenbacherWord(Pkcs1Vector vector) {
        super(TlsWordType.BLEICHENBACHER);
        vector.setEncryptedValue(
                ArrayConverter.hexStringToByteArray(
                        "526564616374656420666f7220616e6f6e796d697479"));
        this.vector = vector;
    }

    @Override
    public ResponseFingerprint execute(State state, ReceiveHint receiveHint) {
        RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage();
        cke.setPublicKey(
                Modifiable.explicit(getVectorForMostRecentPublicKey(state).getEncryptedValue()));
        sendMessage(cke, new Record(), state);
        return receiveMessages(state, receiveHint);
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.getVector().getName());
        return hash;
    }

    @Override
    public String toString() {
        return "Bleichenbacher{vector=" + getVector().getName() + "}";
    }

    @Override
    public String toShortString() {
        return "Bleichenbacher";
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
        final BleichenbacherWord other = (BleichenbacherWord) obj;
        return Objects.equals(this.getVector().getName(), other.getVector().getName());
    }

    public Pkcs1Vector getVector() {
        return vector;
    }

    private Pkcs1Vector getVectorForMostRecentPublicKey(State state) {
        if (state.getTlsContext().getServerRSAModulus() != null
                && state.getTlsContext().getServerRSAPublicKey() != null) {
            try {
                RSAPublicKeySpec keySpec =
                        new RSAPublicKeySpec(
                                state.getTlsContext().getServerRSAModulus(),
                                state.getTlsContext().getServerRSAPublicKey());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
                List<Pkcs1Vector> generatePkcs1Vectors =
                        Pkcs1VectorGenerator.generatePkcs1Vectors(
                                publicKey, BleichenbacherScanType.FAST, ProtocolVersion.TLS12);
                for (Pkcs1Vector newVector : generatePkcs1Vectors) {
                    if (newVector.getName().equals(vector.getName())) {
                        return newVector;
                    }
                }
            } catch (Exception ex) {
                LOG.error("Failed to generate new vector: ", ex);
            }
        }
        return vector;
    }
}
