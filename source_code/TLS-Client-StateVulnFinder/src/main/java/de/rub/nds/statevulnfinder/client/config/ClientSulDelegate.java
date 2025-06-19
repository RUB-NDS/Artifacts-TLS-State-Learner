/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.config;

import com.beust.jcommander.Parameters;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Parameters(
        commandDescription =
                "Learn a client implementation, thus start TLS-Attacker in server mode")
public class ClientSulDelegate extends ServerDelegate {
    private static final Logger LOGGER = LogManager.getLogger();

    private final VulnerabilityFinderConfig finderConfig;

    public ClientSulDelegate(VulnerabilityFinderConfig finderConfig) {
        super();
        this.finderConfig = finderConfig;
    }

    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);
        config.getDefaultServerConnection().setHostname("localhost");
        config.getDefaultServerConnection().setTimeout(finderConfig.getMinTimeout());
        config.getDefaultServerConnection().setFirstTimeout(finderConfig.getMinTimeout());
        config.getDefaultServerConnection().setConnectionTimeout(finderConfig.getMinTimeout());
    }
}
