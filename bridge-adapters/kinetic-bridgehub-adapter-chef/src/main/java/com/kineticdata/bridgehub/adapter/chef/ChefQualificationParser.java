package com.kineticdata.bridgehub.adapter.chef;

import com.kineticdata.bridgehub.adapter.QualificationParser;

public class ChefQualificationParser extends QualificationParser {
    public String encodeParameter(String name, String value) {
        return value;
    }
}
