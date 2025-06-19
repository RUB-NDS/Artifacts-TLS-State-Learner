/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.config;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.statevulnfinder.core.constants.TransportType;
import java.util.Arrays;

public class TransportTypeConverter implements IStringConverter<TransportType> {

    @Override
    public TransportType convert(String value) {
        try {
            return TransportType.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new ParameterException(
                    "Value "
                            + value
                            + " cannot be converted to a TransportType. "
                            + "Available values are: "
                            + Arrays.toString(TransportType.values()));
        }
    }
}
