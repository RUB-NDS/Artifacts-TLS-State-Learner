/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public abstract class RSAPublicKeySelector {
    private static CertificateReport selectBleichenbacherRSACertReport(
            List<CertificateChain> certChains) {
        CertificateReport rsaCertReport = null;
        if (certChains != null) {
            for (CertificateChain certChain : certChains) {
                if (certChain.getCertificateReportList() != null) {
                    for (int i = certChain.getCertificateReportList().size() - 1; i >= 0; i--) {
                        CertificateReport report = certChain.getCertificateReportList().get(i);
                        if (report.getLeafCertificate() != null
                                && report.getLeafCertificate()
                                && report.getPublicKey() instanceof CustomRsaPublicKey) {
                            return report;
                            // return (RSAPublicKey)
                            // certReport.convertToX509Certificate().getPublicKey();
                        } else if (report.getPublicKey() instanceof CustomRsaPublicKey
                                && (rsaCertReport == null
                                        || (keyUsageLeafPlausible(report)
                                                && !keyUsageLeafPlausible(rsaCertReport)))) {
                            rsaCertReport = report;
                        }
                    }
                }
            }
        }
        return rsaCertReport;
    }

    private static boolean keyUsageLeafPlausible(CertificateReport certReport) {
        final int KEY_ENCIPHERMENT = 2;
        final int KEY_AGREEMENT = 4;
        final int ENCIPHERMENT_ONLY = 7;
        boolean[] keyUsage = certReport.convertToX509Certificate().getKeyUsage();
        if (keyUsage != null && keyUsage.length > 0) {
            if ((keyUsage.length > KEY_ENCIPHERMENT && keyUsage[KEY_ENCIPHERMENT])
                    || (keyUsage.length > KEY_AGREEMENT && keyUsage[KEY_AGREEMENT])
                    || (keyUsage.length > ENCIPHERMENT_ONLY && keyUsage[ENCIPHERMENT_ONLY])) {
                return true;
            }
        }
        return false;
    }

    public static RSAPublicKey getEncodedRSAPublicKey(List<CertificateChain> certChains) {
        CertificateReport rsaCertReport = selectBleichenbacherRSACertReport(certChains);
        if (rsaCertReport == null) {
            return null;
        }
        return (RSAPublicKey) rsaCertReport.convertToX509Certificate().getPublicKey();
    }

    public static CustomRsaPublicKey getCustomRSAPublicKey(List<CertificateChain> certChains) {
        CertificateReport rsaCertReport = selectBleichenbacherRSACertReport(certChains);
        if (rsaCertReport == null) {
            return null;
        }
        return (CustomRsaPublicKey) rsaCertReport.getPublicKey();
    }
}
