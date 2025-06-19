/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import de.rub.nds.statevulnfinder.core.algorithm.words.BleichenbacherWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans.BleichenbacherScanType;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1Vector;
import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1VectorGenerator;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class BleichenbacherOracleWords {

    public static Map<String, TlsWord> getAll(ServerReport report) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        RSAPublicKey rsaPublicKey =
                RSAPublicKeySelector.getEncodedRSAPublicKey(report.getCertificateChainList());
        if (rsaPublicKey != null) {
            List<Pkcs1Vector> generatePkcs1Vectors =
                    Pkcs1VectorGenerator.generatePkcs1Vectors(
                            rsaPublicKey, BleichenbacherScanType.FAST, ProtocolVersion.TLS12);
            for (Pkcs1Vector vector : generatePkcs1Vectors) {
                wordMap.put("BB_" + vector.getName(), new BleichenbacherWord(vector));
            }
        }
        return wordMap;
    }
}
