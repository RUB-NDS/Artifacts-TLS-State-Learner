/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.vector.Pkcs1Vector;
import jakarta.xml.bind.annotation.adapters.XmlAdapter;

public class Pkcs1VectorAdapter extends XmlAdapter<Pkcs1Vector, Pkcs1Vector> {
    public static boolean anonymize = false;

    @Override
    public Pkcs1Vector unmarshal(Pkcs1Vector v) {
        return v;
    }

    @Override
    public Pkcs1Vector marshal(Pkcs1Vector v) {
        if (anonymize) {

            if (v != null) {
                v.setEncryptedValue(
                        java.util.Base64.getDecoder().decode("UmVkYWN0ZWQgZm9yIGFub255bWl0eX=="));
            }
        }
        return v;
    }
}
