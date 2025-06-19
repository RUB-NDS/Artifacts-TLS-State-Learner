/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.FastMealySULCache;
import de.rub.nds.statevulnfinder.core.extraction.TimeoutHandler;
import de.rub.nds.statevulnfinder.server.ServerVulnerabilityFinder;
import de.rub.nds.statevulnfinder.server.config.ServerSulDelegate;
import de.rub.nds.statevulnfinder.server.sul.TlsServerSul;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Command to run TLS-Scanner to prepare for sending queries. */
public class ScanCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "scan";
    }

    @Override
    public String getDescription() {
        return "Run TLS-Scanner to prepare for sending queries";
    }

    @Override
    public String getUsage() {
        return "scan [<hostname>]";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 0 || args.length == 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        if (context.getConfig() == null) {
            LOG.error("No configuration available. Load a state machine first.");
            return;
        }

        String host = context.getConfig().getDelegate(ServerSulDelegate.class).getHost();
        if (args.length > 0) {
            LOG.info("Overwriting host in delegate with {}:443", args[0]);
            context.getConfig().getDelegate(ServerSulDelegate.class).setHost(args[0] + ":443");
        }

        LOG.info("Starting TLS-Scanner scan...");
        ServerVulnerabilityFinder vulnerabilityFinder =
                new ServerVulnerabilityFinder(context.getConfig());
        context.setVulnerabilityFinder(vulnerabilityFinder);

        ScanReport scanReport = vulnerabilityFinder.scanHost();
        context.setScanReport(scanReport);
        context.setWrittenScanReport(scanReport.getFullReport(ScannerDetail.NORMAL, true));

        LOG.info("Done scanning. Use 'printScan' for details");

        TlsServerSul tlsServerSul = new TlsServerSul(context.getConfig(), scanReport);
        context.setTlsServerSul(tlsServerSul);

        TimeoutHandler timeoutHandler = new TimeoutHandler(context.getConfig());

        // wrap TLS SUL/T in a cache
        FastMealySULCache sulCache =
                new FastMealySULCache(
                        tlsServerSul,
                        context.getStateMachine().getAlphabet(),
                        new ReentrantReadWriteLock(),
                        true,
                        timeoutHandler,
                        context.getConfig());
        context.setSulCache(sulCache);

        LOG.info("TlsServerSul instance created.");
    }
}
