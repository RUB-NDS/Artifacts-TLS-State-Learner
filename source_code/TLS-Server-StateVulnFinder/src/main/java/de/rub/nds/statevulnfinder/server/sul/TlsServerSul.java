/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.sul;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.RSAPublicKeySelector;
import de.rub.nds.statevulnfinder.core.sul.TlsSul;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.session.IdSession;
import de.rub.nds.tlsattacker.core.state.session.Session;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsServerSul extends TlsSul {

    private static final Logger LOG = LogManager.getLogger();

    private NamedGroup keyShareGroup;
    private CipherSuite cipherSuite;
    private CustomRsaPublicKey rsaPublicKey;
    boolean checkForRSAKey = true;

    public TlsServerSul(
            VulnerabilityFinderConfig vulnerabilityFinderConfig, ScanReport scanReport) {
        super(vulnerabilityFinderConfig, scanReport);
    }

    @Override
    public TransportHandler createTcpTransportHandler(Connection connection) {
        return new ClientTcpTransportHandler(connection);
    }

    @Override
    public TransportHandler createUdpTransportHandler(Connection connection) {
        throw new UnsupportedOperationException("UDP is not supported yet");
    }

    @Override
    public void postInitializeAction(State state) {}

    @Override
    public Connection getDefaultConnection(State state) {
        return state.getConfig().getDefaultClientConnection();
    }

    @Override
    protected boolean isTargetSpecificIllegalTransition(TlsWord in, State state) {
        // forbid pointless resumption attempts
        if (in instanceof ResumingClientHelloWord) {
            ResumingClientHelloWord resumingHello = (ResumingClientHelloWord) in;
            if (illegalTls13ResumptionAttempt(resumingHello, state)
                    || illegalTls12ResumptionAttempt(resumingHello, state)) {
                return true;
            }
        } else if (in.getType() == TlsWordType.RESET_CONNECTION && noSessionCached(state)) {
            return true;
        }
        return false;
    }

    /**
     * We use connection resets to analyze the impact of session resumption. Hence, we do not want
     * to explore paths that perform resets before any session has been added to our state.
     *
     * @param state
     * @return
     */
    private static boolean noSessionCached(State state) {
        return state.getTlsContext().getSessionList() == null
                || state.getTlsContext().getSessionList().isEmpty();
    }

    private static boolean illegalTls12ResumptionAttempt(
            ResumingClientHelloWord resumingHello, State state) {
        return resumingHello.getResumptionType()
                        != ResumingClientHelloWord.ResumptionType.TLS_1_3_TICKET
                && (state.getTlsContext().getServerSessionId() == null
                        || state.getTlsContext().getSelectedCipherSuite() == null
                        || state.getTlsContext().getSelectedCipherSuite().isTLS13()
                        || state.getTlsContext().getSessionList() == null
                        || state.getTlsContext().getSessionList().isEmpty()
                        || illegalTls12TicketResumptionAttempt(resumingHello, state));
    }

    private static boolean illegalTls13ResumptionAttempt(
            ResumingClientHelloWord resumingHello, State state) {
        return resumingHello.getResumptionType()
                        == ResumingClientHelloWord.ResumptionType.TLS_1_3_TICKET
                && (state.getTlsContext().getServerSessionId() == null
                        || !state.getTlsContext().getSelectedCipherSuite().isTLS13()
                        || state.getTlsContext().getPskSets() == null
                        || state.getTlsContext().getPskSets().isEmpty());
    }

    private static boolean illegalTls12TicketResumptionAttempt(
            ResumingClientHelloWord resumingHello, State state) {
        boolean noTicketsAvailable =
                state.getTlsContext().getSessionList() == null
                        || !state.getTlsContext().getSessionList().stream()
                                .anyMatch(Session::isTicketSession);
        return (resumingHello.getResumptionType() == ResumingClientHelloWord.ResumptionType.TICKET
                && noTicketsAvailable);
    }

    @Override
    protected void adjustConfigToScanReport(Config config) {
        if (getScanReport() != null) {
            ServerReport serverReport = (ServerReport) getScanReport();

            adjustSniField(serverReport, config);
            adjustNamedGroupFields(serverReport, config);
            adjustCipherSuiteFields(serverReport, config);
            adjustDefaultRSAKeys(serverReport, config);
        }
        // prevent negotiation of Enc-Then-Mac for CBC to test for padding oracles
        config.setAddEncryptThenMacExtension(false);
    }

    private void adjustSniField(ServerReport serverReport, Config config) {
        String hostname = serverReport.getHost();
        if (hostname != null) {
            config.setAddServerNameIndicationExtension(true);
            config.setDefaultSniHostnames(
                    Arrays.asList(
                            new ServerNamePair(
                                    NameType.HOST_NAME.getValue(),
                                    hostname.getBytes(Charset.forName("ASCII")))));
        }
    }

    private void adjustDefaultRSAKeys(ServerReport serverReport, Config config) {
        if (checkForRSAKey) {
            rsaPublicKey =
                    RSAPublicKeySelector.getCustomRSAPublicKey(
                            serverReport.getCertificateChainList());
        }
        if (rsaPublicKey != null) {
            config.setDefaultServerRSAModulus(rsaPublicKey.getModulus());
            config.setDefaultServerRSAPublicKey(rsaPublicKey.getPublicExponent());
        }
    }

    private void adjustCipherSuiteFields(ServerReport serverReport, Config config) {
        if (cipherSuite == null) {
            cipherSuite = getNiceCipherSuite(serverReport);
        }
        config.setDefaultSelectedCipherSuite(cipherSuite);
        config.setDefaultClientSupportedCipherSuites(cipherSuite);
        config.setDefaultServerSupportedCipherSuites(cipherSuite);
    }

    private void adjustNamedGroupFields(ServerReport serverReport, Config config) {
        if (keyShareGroup == null) {
            keyShareGroup = getNiceKeyShareGroup(serverReport);
        }
        config.setDefaultClientNamedGroups(getNiceGroupList(serverReport, keyShareGroup));
        config.setDefaultClientKeyShareNamedGroups(keyShareGroup);
        config.setDefaultSelectedNamedGroup(keyShareGroup);
    }

    private NamedGroup getNiceKeyShareGroup(ServerReport serverReport) {
        if (serverReport.getHelloRetryRequestSelectedNamedGroup() != null) {
            // Some servers, like boringssl, enforce their favorite group
            return serverReport.getHelloRetryRequestSelectedNamedGroup();
        }
        if ((serverReport.getSupportedTls13Groups() == null
                        || serverReport.getSupportedTls13Groups().isEmpty())
                || serverReport.getSupportedTls13Groups().contains(NamedGroup.SECP256R1)) {
            return NamedGroup.SECP256R1;
        }
        return serverReport.getSupportedTls13Groups().get(0);
    }

    private List<NamedGroup> getNiceGroupList(ServerReport serverReport, NamedGroup keyShareGroup) {
        List<NamedGroup> groupList = new LinkedList<>();
        if (serverReport.getSupportedNamedGroups() != null) {
            groupList.addAll(serverReport.getSupportedNamedGroups());
        }
        groupList.remove(keyShareGroup);
        groupList.add(0, keyShareGroup);
        return groupList;
    }

    /**
     * While sending a CKE message, we always derive a new session. If no new SessionID was provided
     * by the server yet, this may result in an invalid session that has the same SessionID as a
     * previous benign one. Later on, TLS-Attacker would attempt to use this SessionID and the
     * server would recognize the ID but use a different master secret than TLS-Attacker, which
     * results in a (SH, CCS, UNKNOWN) which we want to avoid.
     */
    private void restoreBrokenSessionCache(State state) {
        byte[] contextClientSessionId = state.getTlsContext().getClientSessionId();
        if (state.getTlsContext().getSessionList() != null && contextClientSessionId != null) {
            List<IdSession> idSessions =
                    state.getTlsContext().getSessionList().stream()
                            .filter(Session::isIdSession)
                            .map(session -> (IdSession) session)
                            .collect(Collectors.toList());
            IdSession firstMatchingSession = null;
            for (IdSession session : idSessions) {
                if (Arrays.equals(session.getId(), contextClientSessionId)
                        && firstMatchingSession != null
                        && !Arrays.equals(
                                session.getMasterSecret(),
                                firstMatchingSession.getMasterSecret())) {
                    state.getTlsContext().getSessionList().remove(session);
                } else if (Arrays.equals(session.getId(), contextClientSessionId)
                        && firstMatchingSession == null) {
                    firstMatchingSession = session;
                }
            }
        }
    }

    private CipherSuite getNiceCipherSuite(ServerReport serverReport) {
        CipherSuite preTls12CipherSuite = null;
        CipherSuite tls13CipherSuite = null;
        if (serverReport.getVersionSuitePairs() != null) {
            for (VersionSuiteListPair versionSuitePair : serverReport.getVersionSuitePairs()) {
                if (!versionSuitePair.getCipherSuiteList().isEmpty()) {
                    if (versionSuitePair.getVersion() == ProtocolVersion.TLS12) {
                        return versionSuitePair.getCipherSuiteList().get(0);
                    } else if (versionSuitePair.getVersion() == ProtocolVersion.TLS13) {
                        tls13CipherSuite = versionSuitePair.getCipherSuiteList().get(0);
                    } else if (!versionSuitePair.getVersion().isSSL()) {
                        preTls12CipherSuite = versionSuitePair.getCipherSuiteList().get(0);
                    }
                }
            }
        }
        if (preTls12CipherSuite != null) {
            return preTls12CipherSuite;
        } else if (tls13CipherSuite != null) {
            return tls13CipherSuite;
        } else {
            return CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
        }
    }

    @Override
    protected void steppedCleanup(TlsWord in, State state, SulResponse sulResponse) {
        if (in.getType() == TlsWordType.CLIENT_KEY_EXCHANGE) {
            restoreBrokenSessionCache(state);
        }
    }
}
