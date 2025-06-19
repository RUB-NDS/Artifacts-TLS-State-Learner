/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.util;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class ConnectivityChecker {
    public static final String IP_CLOUDFLARE = "1.1.1.1";
    public static final String IP_GOOGLE = "8.8.8.8";
    // we use 443 to detect potential port-related issues as most of our TLS scans will target 443
    public static final int PORT = 443;

    public static boolean connectionIsAlive() {
        return isReachable(IP_CLOUDFLARE) || isReachable(IP_GOOGLE);
    }

    private static boolean isReachable(String ip) {
        try (Socket socket = new Socket()) {
            InetSocketAddress address = new InetSocketAddress(ip, PORT);
            socket.connect(address, 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
