package org.wso2.carbon.identity.core.model;

public class SAMLSSOAttribute {
    private int id;
    private String issuer_name;
    private String prop_key;
    private String prop_value;
    private int tenant_id;

    public SAMLSSOAttribute(int id, String issuer_name, String prop_key, String prop_value, int tenant_id) {
        this.id = id;
        this.issuer_name = issuer_name;
        this.prop_key = prop_key;
        this.prop_value = prop_value;
        this.tenant_id = tenant_id;
    }

    public SAMLSSOAttribute(String issuer_name, String prop_key, String prop_value, int tenant_id) {
        this.issuer_name = issuer_name;
        this.prop_key = prop_key;
        this.prop_value = prop_value;
        this.tenant_id = tenant_id;
    }

    public int getId() {
        return id;
    }

    public String getIssuer_name() {
        return issuer_name;
    }

    public String getProp_key() {
        return prop_key;
    }

    public String getProp_value() {
        return prop_value;
    }

    public int getTenant_id() {
        return tenant_id;
    }
}

