/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.learnlib.api.exception.SULException;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.exception.LimitExceededException;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.util.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.io.IOException;
import java.util.LinkedList;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Note: SUT = System Under Test SUL = System Under Learning
 *
 * @author robert
 */
public abstract class TlsSul implements HintedSUL<TlsWord, SulResponse> {

    private static final Logger LOG = LogManager.getLogger();

    private State state = null;

    private boolean closed = false;

    private long resetWait = 0;

    private long connectionCount = 0;

    private long majorityVoteConnectionCount = 0;

    private final Delegate delegate;

    private final boolean manageProcess;

    private TlsWord previousWord;

    protected final VulnerabilityFinderConfig vulnerabilityFinderConfig;

    protected ProcessHandler processHandler;

    private final ScanReport scanReport;

    private boolean confirmingVulnerabilities = false;

    public TlsSul(VulnerabilityFinderConfig vulnerabilityFinderConfig, ScanReport scanReport) {
        this.delegate = vulnerabilityFinderConfig.getSulDelegate();
        this.vulnerabilityFinderConfig = vulnerabilityFinderConfig;
        this.manageProcess = vulnerabilityFinderConfig.getCommand() != null;
        this.scanReport = scanReport;
        if (manageProcess) {
            this.processHandler = new ProcessHandler(vulnerabilityFinderConfig);
        }
    }

    private State prepareState() {
        Config config = vulnerabilityFinderConfig.createConfig();
        config.setEnforceSettings(false);
        config.setStopActionsAfterFatal(false);
        config.setStopReceivingAfterFatal(false);
        config.setAddServerNameIndicationExtension(true);
        config.setAddRenegotiationInfoExtension(Boolean.TRUE);
        config.setAddSignatureAndHashAlgorithmsExtension(Boolean.TRUE);
        config.setAddHeartbeatExtension(true);
        delegate.applyDelegate(config);

        // the fields below may get overwritten by a ScanReport
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        config.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        config.setDefaultServerSupportedCipherSuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        config.setAddEllipticCurveExtension(false);
        config.setAddECPointFormatExtension(false);
        config.setDefaultClientNamedGroups(NamedGroup.SECP256R1);
        config.setDefaultClientKeyShareNamedGroups(NamedGroup.SECP256R1);
        config.setDefaultSelectedNamedGroup(NamedGroup.SECP256R1);

        adjustConfigToScanReport(config);
        state = new State(config);
        return state;
    }

    public abstract TransportHandler createTcpTransportHandler(Connection connection);

    public abstract TransportHandler createUdpTransportHandler(Connection connection);

    public abstract void postInitializeAction(State state);

    public abstract Connection getDefaultConnection(State state);

    public State getState() {
        return state;
    }

    @Override
    public void pre() {
        state = prepareState();
        Connection connection = getDefaultConnection(state);
        connection.setConnectionTimeout(10000);
        switch (vulnerabilityFinderConfig.getTransport()) {
            case TCP:
                state.getTlsContext().setTransportHandler(createTcpTransportHandler(connection));
                break;
            case UDP:
                // TODO: implement UDP
                state.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS12);
                state.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS10);
                state.getTlsContext().setTransportHandler(createUdpTransportHandler(connection));
        }
        establishConnection();
        postInitializeAction(state);

        closed = false;
        previousWord = null;
        resetWait = vulnerabilityFinderConfig.getResetWait();

        if (connectionCount % 500 == 0) {
            LOG.info(
                    "Start connection {} for {}",
                    connectionCount,
                    vulnerabilityFinderConfig.getImplementationName());
        }
        if (mustStopDueToConnectionLimit()) {
            throw new LimitExceededException(LimitExceededException.LimitationType.CONNECTION);
        }
        connectionCount++;
    }

    public void sleepFor(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ex) {
            LOG.error("Failed to pause state learning", ex);
        }
    }

    private void establishConnection() {
        int initializationAttempts = 0;
        boolean retryInitialization = false;
        boolean pausedAndRetried = false;
        do {
            try {
                initializationAttempts++;
                state.getTlsContext().getTransportHandler().preInitialize();
                if (manageProcess) {
                    processHandler.launchProcess();
                }
                state.getTlsContext().getTransportHandler().initialize();
                retryInitialization = false;
            } catch (IOException ex) {
                if (initializationAttempts >= 3) {
                    boolean connectionHealthy = ConnectivityChecker.connectionIsAlive();
                    if (connectionHealthy && !pausedAndRetried) {
                        LOG.warn(
                                "Initialization to {} failed but Internet connection seems healthy. Will sleep and retry once more in 2h.",
                                vulnerabilityFinderConfig.getImplementationName());
                        sleepFor(7200000);
                        initializationAttempts = 0;
                        pausedAndRetried = true;
                        retryInitialization = true;
                    } else if (!connectionHealthy) {
                        LOG.warn(
                                "Internet connection seems to be down. Waiting 10 minutes for next check before continuing {}",
                                vulnerabilityFinderConfig.getImplementationName());
                        sleepFor(600000);
                        initializationAttempts = 0;
                        pausedAndRetried = false;
                        retryInitialization = true;
                    } else if (connectionHealthy && pausedAndRetried) {
                        LOG.warn(
                                "Still unable to reconnect to {} after 2h. Aborting learning.",
                                vulnerabilityFinderConfig.getImplementationName());
                        throw new LimitExceededException(
                                LimitExceededException.LimitationType.INITIALIZATION);
                    }
                } else {
                    retryInitialization = true;
                }
            }
        } while (retryInitialization);
    }

    @Override
    public void post() {
        if (previousWord == null) {
            LOG.error("POST without any word sent");
        }
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ex) {
            LOG.error("Could not close connections");
        }

        resetWait();

        if (manageProcess) {
            processHandler.terminateProcess();
        }
        state = null;
    }

    private void resetWait() {
        try {
            if (resetWait > 0) {
                Thread.sleep(resetWait);
            }
        } catch (InterruptedException ex) {
            LOG.error("Could not sleep thread");
            LOG.error(ex, null);
        }
    }

    @Override
    public SulResponse step(TlsWord in) throws SULException {
        return stepWithHint(in, new ReceiveHint(null));
    }

    @Override
    public SulResponse stepWithHint(TlsWord in, ReceiveHint receiveHint) {
        SulResponse sulResponse;
        if (isIllegalTransition(in)) {
            sulResponse = new SulResponse(true);
        } else {
            LOG.debug("sending:" + in.toString());
            sulResponse = new SulResponse(in.execute(state, receiveHint));

            if (isFailedResumptionAttempt(in, sulResponse)) {
                sulResponse = new SulResponse(true);
            } else {
                clearSessionCacheOnFullHandshake(in, sulResponse);
            }
            LOG.debug("received:" + sulResponse);
        }

        if (sulResponse.getResponseFingerprint().getSocketState() == SocketState.CLOSED
                || sulResponse.getResponseFingerprint().getSocketState()
                        == SocketState.SOCKET_EXCEPTION) {
            closed = true;
        } else if (sulResponse.getResponseFingerprint().getSocketState() == SocketState.UP) {
            closed = false;
        }

        steppedCleanup(in, state, sulResponse);
        previousWord = in;
        return sulResponse;
    }

    /**
     * Answers the given query with a majority vote with count many votes.
     *
     * @param query The query which this methods answers
     * @param count How often the query will be made to the server before giving the majority vote
     * @return The result of the server based on the majority vote.
     */
    public Word<SulResponse> majorityVote(Word<TlsWord> query, int count) {
        LinkedList<Word<SulResponse>> voteList = new LinkedList<>();
        for (int i = 0; i < count; i++) {
            WordBuilder<SulResponse> wordBuilder = new WordBuilder<>();
            this.pre();
            majorityVoteConnectionCount++;
            // build our answer for each TlsWord in the query
            for (TlsWord word : query) {
                wordBuilder.append(step(word));
            }
            this.post();
            // add the complete word into the voting list
            voteList.add(wordBuilder.toWord());
        }
        return majorityElement(voteList);
    }

    /**
     * Finds the word with the most occurrences in the given list. See "Boyer–Moore majority vote
     * algorithm".
     *
     * @param words List in which to find the most frequently occurring element.
     * @return The word with the most occurrences in the given list.
     */
    private Word<SulResponse> majorityElement(LinkedList<Word<SulResponse>> words) {
        Word<SulResponse> majorityWord = words.get(0);
        int counter = 1;
        for (Word<SulResponse> word : words) {
            if (counter == 0) {
                majorityWord = word;
                counter = 1;
            } else if (word.equals(majorityWord)) {
                counter++;
            } else {
                counter--;
            }
        }
        return majorityWord;
    }

    public long getConnectionCount() {
        return connectionCount;
    }

    public long getMajorityVoteConnections() {
        return majorityVoteConnectionCount;
    }

    private boolean isIllegalTransition(TlsWord in) {
        try {
            if (state == null
                    || isTargetSpecificIllegalTransition(in, state)
                    || isIllegalPaddingOracleAttempt(in)
                    || ((state.getTlsContext().getTransportHandler().isClosed() || closed)
                            && !(in instanceof ResetConnectionWord))) {
                return true;
            }
        } catch (IOException ex) {
            closed = true;
            return true;
        }
        return false;
    }

    protected abstract boolean isTargetSpecificIllegalTransition(TlsWord in, State state);

    protected abstract void adjustConfigToScanReport(Config config);

    protected abstract void steppedCleanup(TlsWord in, State state, SulResponse response);

    private boolean isFailedResumptionAttempt(TlsWord in, SulResponse response) {
        if (in.getType() == TlsWordType.RESUMING_HELLO
                && response.getResponseFingerprint().getMessageList() != null) {
            return response.getResponseFingerprint().getMessageList().stream()
                            .anyMatch(msg -> msg instanceof ServerHelloMessage)
                    && response.getResponseFingerprint().getMessageList().stream()
                            .anyMatch(msg -> msg instanceof CertificateMessage);
        }
        return false;
    }

    private boolean isIllegalPaddingOracleAttempt(TlsWord in) {
        if (in.getType() == TlsWordType.PADDING_ORACLE
                && (state.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13
                        || AlgorithmResolver.getCipherType(
                                        state.getTlsContext()
                                                .getRecordLayer()
                                                .getEncryptorCipher()
                                                .getState()
                                                .getCipherSuite())
                                != CipherType.BLOCK)) {
            return true;
        }
        return false;
    }

    private void clearSessionCacheOnFullHandshake(TlsWord in, SulResponse response) {
        if (in.getType().isRegularClientHello()
                && !response.isIllegalTransitionFlag()
                && response.getResponseFingerprint().getMessageList().stream()
                        .anyMatch(msg -> msg instanceof ServerHelloMessage)
                && response.getResponseFingerprint().getMessageList().stream()
                        .anyMatch(msg -> msg instanceof CertificateMessage)) {
            // prevent state multiplier
            state.getTlsContext().getSessionList().clear();
            if (state.getTlsContext().getPskSets() != null) {
                state.getTlsContext().getPskSets().clear();
            }
        }
    }

    public TlsWord getPreviousWord() {
        return previousWord;
    }

    public ScanReport getScanReport() {
        return scanReport;
    }

    public void setConfirmingVulnerabilities(boolean confirmingVulnerabilities) {
        this.confirmingVulnerabilities = confirmingVulnerabilities;
    }

    private boolean mustStopDueToConnectionLimit() {
        return connectionCount >= vulnerabilityFinderConfig.getMaxConnections()
                && vulnerabilityFinderConfig.getMaxConnections() > -1
                && !confirmingVulnerabilities;
    }
}
