/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.statevulnfinder.core.VulnerabilityFinder;
import de.rub.nds.statevulnfinder.server.ServerVulnerabilityFinder;
import de.rub.nds.statevulnfinder.server.config.ServerVulnerabilityFinderConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    private static final Logger LOG = LogManager.getLogger(Main.class.getName());

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        ServerVulnerabilityFinderConfig config =
                new ServerVulnerabilityFinderConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }

            try {
                VulnerabilityFinder finder = new ServerVulnerabilityFinder(config);
                finder.execute();
            } catch (ConfigurationException E) {
                LOG.error(
                        "Encountered a ConfigurationException aborting. See debug for more info.");
                LOG.debug(E);
            } catch (TransportHandlerConnectException E) {
                LOG.error(E.getMessage());
            }
        } catch (ParameterException E) {
            LOG.error("Could not parse provided parameters. " + E.getLocalizedMessage());
            LOG.debug(E);
            commander.usage();
        }
    }
}
