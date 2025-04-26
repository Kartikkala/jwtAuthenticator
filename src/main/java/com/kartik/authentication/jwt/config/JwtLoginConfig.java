package com.kartik.authentication.jwt.config;

import java.util.List;

public class JwtLoginConfig {
    private final String subjectField;
    private final List<String> claimFields;

    public JwtLoginConfig(String subjectField, List<String> claimFields) {
        this.subjectField = subjectField;
        this.claimFields = claimFields;
    }

    public String getSubjectField() {
        return subjectField;
    }

    public List<String> getClaimFields() {
        return claimFields;
    }
}
