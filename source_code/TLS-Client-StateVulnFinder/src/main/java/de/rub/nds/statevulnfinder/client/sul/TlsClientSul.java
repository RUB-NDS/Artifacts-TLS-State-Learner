/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.sul;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.sul.TlsSul;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsClientSul extends TlsSul {

    private static final Logger LOG = LogManager.getLogger();

    public TlsClientSul(
            VulnerabilityFinderConfig vulnerabilityFinderConfig, ScanReport scanReport) {
        super(vulnerabilityFinderConfig, scanReport);
    }

    @Override
    public TransportHandler createTcpTransportHandler(Connection connection) {
        return new ServerTcpTransportHandler(connection);
    }

    @Override
    public TransportHandler createUdpTransportHandler(Connection connection) {
        throw new UnsupportedOperationException("UDP is not implemented");
    }

    @Override
    public void postInitializeAction(State state) {
        // make sure connection is established
        while (state.getTlsContext().getTransportHandler().isInitialized() == false) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException ex) {
                LOG.error(ex);
            }
        }

        // catch initial CH
        GenericReceiveAction action = new GenericReceiveAction("server");
        action.execute(state);
    }

    @Override
    public Connection getDefaultConnection(State state) {
        return state.getConfig().getDefaultServerConnection();
    }

    @Override
    protected boolean isTargetSpecificIllegalTransition(TlsWord in, State state) {
        return false;
    }

    @Override
    protected void adjustConfigToScanReport(Config config) {
        if (getScanReport() != null) {
            // TODO restrict config
        }
    }

    @Override
    protected void steppedCleanup(TlsWord in, State state, SulResponse sulResponse) {
        adjustDigestUponRenegotiation(sulResponse, state);
    }

    private void adjustDigestUponRenegotiation(SulResponse sulResponse, State state)
            throws WorkflowExecutionException {
        if (state.getTlsContext().getSelectedProtocolVersion() != null
                && !state.getTlsContext().getSelectedProtocolVersion().isTLS13()
                && !sulResponse.isIllegalTransitionFlag()
                && sulResponse.getResponseFingerprint().getMessageList().size() == 1
                && sulResponse.getResponseFingerprint().getMessageList().get(0)
                        instanceof ClientHelloMessage) {
            byte[] clientHelloBytes =
                    sulResponse
                            .getResponseFingerprint()
                            .getMessageList()
                            .get(0)
                            .getCompleteResultingMessage()
                            .getValue();
            RenegotiationAction renegAction = new RenegotiationAction();
            renegAction.setConnectionAlias(
                    state.getConfig().getDefaultServerConnection().getAlias());
            renegAction.execute(state);
            state.getTlsContext().getDigest().append(clientHelloBytes);
        }
    }
}
