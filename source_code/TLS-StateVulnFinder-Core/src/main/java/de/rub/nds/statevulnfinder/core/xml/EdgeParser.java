/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.xml;

import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.xml.stream.XMLStreamException;
import net.automatalib.commons.util.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EdgeParser {
    private static Logger LOGGER = LogManager.getLogger(EdgeParser.class);

    public static Pair parse(Map<String, String> keyVals) {
        InputStream stream =
                new ByteArrayInputStream(keyVals.get("label").getBytes(StandardCharsets.UTF_8));
        XmlEdgeLabel label = null;
        try {
            label = EdgeLabelIO.read(stream);
        } catch (JAXBException | XMLStreamException | IOException e) {
            LOGGER.error("Could not deserialize edge label", e);
        }
        return Pair.of(label.getInput(), label.getOutput());
    }
}
