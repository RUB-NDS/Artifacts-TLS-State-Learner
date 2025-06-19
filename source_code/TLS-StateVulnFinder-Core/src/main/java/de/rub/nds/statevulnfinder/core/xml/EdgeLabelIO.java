/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.xml;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.*;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EdgeLabelIO {

    private static Logger LOGGER = LogManager.getLogger(EdgeLabelIO.class);

    private static JAXBContext context;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException {
        if (context == null) {
            Set<Class<? extends XmlEdgeLabel>> classes = Collections.singleton(XmlEdgeLabel.class);
            classes =
                    classes.stream()
                            .filter(item -> !item.isInterface())
                            .collect(Collectors.toSet());
            Class<? extends XmlEdgeLabel>[] classesArray =
                    classes.toArray(new Class[classes.size()]);
            context = JAXBContext.newInstance(classesArray);
        }
        return context;
    }

    public static void write(File file, XmlEdgeLabel serializable)
            throws JAXBException, IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileOutputStream outputStream = new FileOutputStream(file);
        EdgeLabelIO.write(outputStream, serializable);
    }

    public static String write(XmlEdgeLabel serializable) throws JAXBException, IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        EdgeLabelIO.write(stream, serializable);
        stream.flush();
        return stream.toString();
    }

    public static void write(OutputStream outputStream, XmlEdgeLabel serializable)
            throws JAXBException, IOException {
        context = getJAXBContext();
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(serializable, outputStream);
        outputStream.close();
    }

    public static XmlEdgeLabel read(InputStream inputStream)
            throws JAXBException, IOException, XMLStreamException {
        context = getJAXBContext();
        Unmarshaller unmarshaller = context.createUnmarshaller();
        XMLInputFactory xmlFactory = XMLInputFactory.newInstance();
        xmlFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xmlFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlReader = xmlFactory.createXMLStreamReader(inputStream);
        XmlEdgeLabel label = (XmlEdgeLabel) unmarshaller.unmarshal(xmlReader);
        inputStream.close();
        return label;
    }

    public static XmlEdgeLabel copyXmlSerializable(XmlEdgeLabel serializable)
            throws JAXBException, IOException, XMLStreamException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        EdgeLabelIO.write(stream, serializable);
        stream.flush();
        XmlEdgeLabel copiedLabel = EdgeLabelIO.read(new ByteArrayInputStream(stream.toByteArray()));
        return copiedLabel;
    }
}
