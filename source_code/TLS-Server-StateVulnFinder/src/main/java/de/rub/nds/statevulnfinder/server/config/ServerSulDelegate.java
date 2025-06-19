/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.config;

import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class ServerSulDelegate extends ClientDelegate {

    private final VulnerabilityFinderConfig finderConfig;

    public ServerSulDelegate(VulnerabilityFinderConfig finderConfig) {
        super();
        this.finderConfig = finderConfig;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        super.applyDelegate(config);
        config.getDefaultClientConnection().setTimeout(finderConfig.getMinTimeout());
        config.getDefaultClientConnection().setFirstTimeout(finderConfig.getMinTimeout());
        config.getDefaultClientConnection().setConnectionTimeout(finderConfig.getMinTimeout());
    }

    public VulnerabilityFinderConfig getVulnerabilityFinderConfig() {
        return finderConfig;
    }
}
