/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.statevulnfinder.client.ClientVulnerabilityFinder;
import de.rub.nds.statevulnfinder.client.config.ClientVulnerabilityFinderConfig;
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
        ClientVulnerabilityFinderConfig config =
                new ClientVulnerabilityFinderConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }

            try {
                ClientVulnerabilityFinder finder = new ClientVulnerabilityFinder(config);
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
