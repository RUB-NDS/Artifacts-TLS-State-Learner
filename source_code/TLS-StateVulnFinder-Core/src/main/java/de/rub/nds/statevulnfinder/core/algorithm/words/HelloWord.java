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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class HelloWord extends TlsWord {

    protected CipherSuite cipherSuite;

    public HelloWord() {}

    public HelloWord(CipherSuite cipherSuite) {
        super(TlsWordType.HELLO);
        this.cipherSuite = cipherSuite;
    }

    public HelloWord(TlsWordType explicitType, CipherSuite cipherSuite) {
        super(explicitType);
        this.cipherSuite = cipherSuite;
    }

    public CipherSuite getSuite() {
        return cipherSuite;
    }

    @Override
    public String toString() {
        return getHelloType() + "HelloWord{" + "suite=" + cipherSuite + '}';
    }

    @Override
    public String toShortString() {
        if (cipherSuite.isTLS13()) {
            return "Tls13" + getHelloType() + "Hello";
        } else if (cipherSuite.name().contains("EC")) {
            return "EC" + getHelloType() + "Hello";
        } else if (cipherSuite.name().contains("DH")) {
            return "DH" + getHelloType() + "Hello";
        } else if (cipherSuite.name().contains("RSA")) {
            return "RSA" + getHelloType() + "Hello";
        } else {
            return getHelloType() + "Hello";
        }
    }

    public abstract String getHelloType();
}
