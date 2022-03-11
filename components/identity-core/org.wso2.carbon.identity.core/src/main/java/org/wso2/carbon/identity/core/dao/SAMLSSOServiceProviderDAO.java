
/*
 * Copyright 2005-2007 WSO2, Inc. (http://wso2.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.core.dao;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.CertificateRetriever;
import org.wso2.carbon.identity.core.CertificateRetrievingException;
import org.wso2.carbon.identity.core.DatabaseCertificateRetriever;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.KeyStoreCertificateRetriever;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import static org.wso2.carbon.identity.core.util.JdbcUtils.isH2DB;

/**
 * DAO for SAMLSSO Service Provider database operations.
 */
public class SAMLSSOServiceProviderDAO {

    private static final String CERTIFICATE_PROPERTY_NAME = "CERTIFICATE";
    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID = "SELECT " +
            "META.VALUE FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 = "SELECT " +
            "META.`VALUE` FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private static Log log = LogFactory.getLog(SAMLSSOServiceProviderDAO.class);

    public static final String ISSUER = "issuer";
    public static final String ISSUER_QUALIFIER = "issuerQualifier";
    public static final String ASSERTION_CONSUMER_URLS = "assertionConsumerUrls";
    public static final String DEFAULT_ASSERTION_CONSUMER_URL = "defaultAssertionConsumerUrl";
    public static final String SIGNING_ALGORITHM_URI = "signingAlgorithmURI";
    public static final String DIGEST_ALGORITHM_URI = "digestAlgorithmURI";
    public static final String ASSERTION_ENCRYPTION_ALGORITHM_URI = "assertionEncryptionAlgorithmURI";
    public static final String KEY_ENCRYPTION_ALGORITHM_URI = "keyEncryptionAlgorithmURI";
    public static final String CERT_ALIAS = "certAlias";
    public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attributeConsumingServiceIndex";
    public static final String DO_SIGN_RESPONSE = "doSignResponse";
    public static final String DO_SINGLE_LOGOUT = "doSingleLogout";
    public static final String DO_FRONT_CHANNEL_LOGOUT = "doFrontChannelLogout";
    public static final String FRONT_CHANNEL_LOGOUT_BINDING = "frontChannelLogoutBinding";
    public static final String IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED = "isAssertionQueryRequestProfileEnabled";
    public static final String SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES = "supportedAssertionQueryRequestTypes";
    public static final String ENABLE_SAML2_ARTIFACT_BINDING = "enableSAML2ArtifactBinding";
    public static final String DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE = "doValidateSignatureInArtifactResolve";
    public static final String LOGIN_PAGE_URL = "loginPageURL";
    public static final String SLO_RESPONSE_URL = "sloResponseURL";
    public static final String SLO_REQUEST_URL = "sloRequestURL";
    public static final String REQUESTED_CLAIMS = "requestedClaims";
    public static final String REQUESTED_AUDIENCES = "requestedAudiences";
    public static final String REQUESTED_RECIPIENTS = "requestedRecipients";
    public static final String ENABLE_ATTRIBUTES_BY_DEFAULT = "enableAttributesByDefault";
    public static final String NAME_ID_CLAIM_URI = "nameIdClaimUri";
    public static final String NAME_ID_FORMAT = "nameIDFormat";
    public static final String IDP_INIT_SSO_ENABLED = "idPInitSSOEnabled";
    public static final String IDP_INIT_SLO_ENABLED = "idPInitSLOEnabled";
    public static final String IDP_INIT_SLO_RETURN_TO_URLS = "idpInitSLOReturnToURLs";
    public static final String DO_ENABLE_ENCRYPTED_ASSERTION = "doEnableEncryptedAssertion";
    public static final String DO_VALIDATE_SIGNATURE_IN_REQUESTS = "doValidateSignatureInRequests";
    public static final String IDP_ENTITY_ID_ALIAS = "idpEntityIDAlias";

    private final int tenantId;

    @Deprecated
    public SAMLSSOServiceProviderDAO(Registry registry) {
        UserRegistry userRegistry = (UserRegistry) registry;
        this.tenantId = userRegistry.getTenantId();
    }

    public SAMLSSOServiceProviderDAO(int tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Add the service provider information to the database.
     *
     * @param serviceProviderDO Service provider information object.
     * @return True if addition successful.
     * @throws IdentityException Error while persisting to the database.
     */
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO) throws IdentityException {

        if (serviceProviderDO == null || serviceProviderDO.getIssuer() == null ||
                StringUtils.isBlank(serviceProviderDO.getIssuer())) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        // If an issuer qualifier value is specified, it is appended to the end of the issuer value.
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(getIssuerWithQualifier(serviceProviderDO.getIssuer(),
                    serviceProviderDO.getIssuerQualifier()));
        }

        if (isServiceProviderExists(serviceProviderDO.getIssuer())) {
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier name "
                            + serviceProviderDO.getIssuerQualifier());
                } else {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + serviceProviderDO.getIssuer());
                }
            }
            return false;
        }

        HashMap<String, LinkedHashSet<String>> pairMap = convertServiceProviderDOToMap(serviceProviderDO);
        String issuerName = serviceProviderDO.getIssuer();

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SAMLSSOSQLQueries.ADD_SAML_APP);
            prepStmt.setString(1, issuerName);
            prepStmt.setInt(4, this.tenantId);
            for (Map.Entry<String, LinkedHashSet<String>> entry : pairMap.entrySet()) {
                for (String value : entry.getValue()) {
                    prepStmt.setString(2, entry.getKey());
                    prepStmt.setString(3, value);
                    prepStmt.addBatch();
                }
            }
            prepStmt.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String msg = "Error adding new service provider to the database with issuer" +
                    serviceProviderDO.getIssuer();
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return true;
    }


    /**
     * Get the issuer value by removing the qualifier.
     *
     * @param issuerWithQualifier issuer value saved in the registry.
     * @return issuer value given as 'issuer' when configuring SAML SP.
     */
    private String getIssuerWithoutQualifier(String issuerWithQualifier) {

        String issuerWithoutQualifier = StringUtils.substringBeforeLast(issuerWithQualifier,
                IdentityRegistryResources.QUALIFIER_ID);
        return issuerWithoutQualifier;
    }

    /**
     * Get the issuer value to be added to registry by appending the qualifier.
     *
     * @param issuer value given as 'issuer' when configuring SAML SP.
     * @return issuer value with qualifier appended.
     */
    private String getIssuerWithQualifier(String issuer, String qualifier) {

        String issuerWithQualifier = issuer + IdentityRegistryResources.QUALIFIER_ID + qualifier;
        return issuerWithQualifier;
    }

    public SAMLSSOServiceProviderDO[] getServiceProviders() throws IdentityException {

        HashMap<String, SAMLSSOServiceProviderDO> serviceProvidersMap = new HashMap<>();
        PreparedStatement prepStmt = null;
        ResultSet results = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        try {
            prepStmt = connection.prepareStatement(SAMLSSOSQLQueries.GET_SAML_APPS);
            prepStmt.setInt(1, this.tenantId);
            results = prepStmt.executeQuery();
            while (results.next()) {
                String issuer = results.getString(1);
                SAMLSSOServiceProviderDO samlssoServiceProviderDO;
                if (serviceProvidersMap.containsKey(issuer)) {
                    samlssoServiceProviderDO = serviceProvidersMap.get(issuer);
                } else {
                    samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
                }
                serviceProvidersMap.put(issuer, updateServiceProviderDO(samlssoServiceProviderDO,
                        results.getString(2), results.getString(3)));
            }
        } catch (SQLException e) {
            String msg = "Error getting all service providers from the database.";
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, results, prepStmt);
        }
        return serviceProvidersMap.values().toArray(new SAMLSSOServiceProviderDO[0]);
    }

    /**
     * Remove the service provider with the given name.
     *
     * @param issuer Name of the SAML issuer.
     * @return True if deletion success.
     * @throws IdentityException Error occurred while removing the SAML service provider from database.
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        if (issuer == null || StringUtils.isEmpty(issuer.trim())) {
            throw new IllegalArgumentException("Trying to delete issuer \'" + issuer + "\'");
        }
        if (!isServiceProviderExists(issuer)) {
            if (log.isDebugEnabled()) {
                log.debug("SAMLSSO Service provider does not exist for the issuer name : " + issuer);
            }
            return false;
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SAMLSSOSQLQueries.REMOVE_SAML_APP_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setInt(2, this.tenantId);
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String msg = "Error removing the service provider from the database with issuer : " + issuer;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return true;
    }

    /**
     * Get the service provider.
     *
     * @param issuer
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer) throws IdentityException {

        if (!isServiceProviderExists(issuer)) {
            if (log.isDebugEnabled()) {
                log.debug("SAMLSSO Service provider does not exist for the issuer name : " + issuer);
            }
            return null;
        }
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();
        PreparedStatement prepStmt = null;
        ResultSet results = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        String tenantDomain = null;
        try {
            tenantDomain = IdentityTenantUtil.getRealmService().getTenantManager().getDomain(this.tenantId);
            prepStmt = connection.prepareStatement(SAMLSSOSQLQueries.GET_SAML_APP_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setInt(2, this.tenantId);
            results = prepStmt.executeQuery();
            while (results.next()) {
                updateServiceProviderDO(serviceProviderDO, results.getString(1), results.getString(2));
            }
            // Load the certificate stored in the database, if signature validation is enabled..
            if (serviceProviderDO.isDoValidateSignatureInRequests() ||
                    serviceProviderDO.isDoValidateSignatureInArtifactResolve() ||
                    serviceProviderDO.isDoEnableEncryptedAssertion()) {
                Tenant tenant = new Tenant();
                tenant.setDomain(tenantDomain);
                tenant.setId(this.tenantId);

                serviceProviderDO.setX509Certificate(getApplicationCertificate(serviceProviderDO, tenant));
            }
        } catch (UserStoreException e) {
            throw new IdentityException("Error occurred while getting tenant domain from tenant ID : " +
                    this.tenantId, e);
        } catch (SQLException e) {
            String msg = "Error getting service provider from the database with issuer : " + issuer;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } catch (CertificateRetrievingException e) {
            throw new IdentityException(String.format("An error occurred while getting the " +
                    "application certificate for validating the requests from the issuer '%s'", issuer), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, results, prepStmt);
        }
        return serviceProviderDO;
    }

    /**
     * Returns the {@link java.security.cert.Certificate} which should used to validate the requests
     * for the given service provider.
     *
     * @param serviceProviderDO
     * @param tenant
     * @return
     * @throws SQLException
     * @throws CertificateRetrievingException
     */
    private X509Certificate getApplicationCertificate(SAMLSSOServiceProviderDO serviceProviderDO, Tenant tenant)
            throws SQLException, CertificateRetrievingException {

        // Check whether there is a certificate stored against the service provider (in the database)
        int applicationCertificateId = getApplicationCertificateId(serviceProviderDO.getIssuer(), tenant.getId());

        CertificateRetriever certificateRetriever;
        String certificateIdentifier;
        if (applicationCertificateId != -1) {
            certificateRetriever = new DatabaseCertificateRetriever();
            certificateIdentifier = Integer.toString(applicationCertificateId);
        } else {
            certificateRetriever = new KeyStoreCertificateRetriever();
            certificateIdentifier = serviceProviderDO.getCertAlias();
        }

        return certificateRetriever.getCertificate(certificateIdentifier, tenant);
    }

    /**
     * Returns the certificate reference ID for the given issuer (Service Provider) if there is one.
     *
     * @param issuer
     * @return
     * @throws SQLException
     */
    private int getApplicationCertificateId(String issuer, int tenantId) throws SQLException {

        try {
            String sqlStmt = isH2DB() ? QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 :
                    QUERY_TO_GET_APPLICATION_CERTIFICATE_ID;
            try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                 PreparedStatement statementToGetApplicationCertificate =
                         connection.prepareStatement(sqlStmt)) {
                statementToGetApplicationCertificate.setString(1, CERTIFICATE_PROPERTY_NAME);
                statementToGetApplicationCertificate.setString(2, issuer);
                statementToGetApplicationCertificate.setInt(3, tenantId);

                try (ResultSet queryResults = statementToGetApplicationCertificate.executeQuery()) {
                    if (queryResults.next()) {
                        return queryResults.getInt(1);
                    }
                }
            }
            return -1;
        } catch (DataAccessException e) {
            String errorMsg = "Error while retrieving application certificate data for issuer: " + issuer +
                    " and tenant Id: " + tenantId;
            throw new SQLException(errorMsg, e);
        }
    }

    public boolean isServiceProviderExists(String issuer) throws IdentityException {

        PreparedStatement prepStmt = null;
        ResultSet results = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        try {
            prepStmt = connection.prepareStatement(SAMLSSOSQLQueries.CHECK_SAML_APP_EXISTS_BY_ISSUER);
            prepStmt.setString(1, issuer);
            prepStmt.setInt(2, this.tenantId);
            results = prepStmt.executeQuery();
            if (results.next()) {
                return true;
            }
        } catch (SQLException e) {
            String msg = "Error checking service provider from the database with issuer : " + issuer;
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, results, prepStmt);
        }
        return false;
    }

    /**
     * Upload service Provider using metadata file..
     *
     * @param serviceProviderDO Service provider information object.
     * @return True if upload success.
     * @throws IdentityException Error occurred while adding the information to database.
     */
    public SAMLSSOServiceProviderDO uploadServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO) throws
            IdentityException {

        if (serviceProviderDO == null || serviceProviderDO.getIssuer() == null) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(getIssuerWithQualifier(serviceProviderDO.getIssuer(),
                    serviceProviderDO.getIssuerQualifier()));
        }

        if (serviceProviderDO.getDefaultAssertionConsumerUrl() == null) {
            throw new IdentityException("No default assertion consumer URL provided for service provider :" +
                    serviceProviderDO.getIssuer());
        }

        if (isServiceProviderExists(serviceProviderDO.getIssuer())) {
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier name "
                            + serviceProviderDO.getIssuerQualifier());
                } else {
                    log.debug("SAML2 Service Provider already exists with the same issuer name "
                            + serviceProviderDO.getIssuer());
                }
            }
            throw IdentityException.error("A Service Provider already exists.");
        }

        HashMap<String, LinkedHashSet<String>> pairMap = convertServiceProviderDOToMap(serviceProviderDO);
        String issuerName = serviceProviderDO.getIssuer();

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);

        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SAMLSSOSQLQueries.ADD_SAML_APP);
            prepStmt.setString(1, issuerName);
            prepStmt.setInt(4, this.tenantId);
            for (Map.Entry<String, LinkedHashSet<String>> entry : pairMap.entrySet()) {
                for (String value : entry.getValue()) {
                    prepStmt.setString(2, entry.getKey());
                    prepStmt.setString(3, value);
                    prepStmt.addBatch();
                }
            }
            prepStmt.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String msg = "Error adding new service provider to the database with issuer" +
                    serviceProviderDO.getIssuer();
            log.error(msg, e);
            throw new IdentityException(msg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return serviceProviderDO;

    }

    private HashMap<String, LinkedHashSet<String>> convertServiceProviderDOToMap(SAMLSSOServiceProviderDO
                                                                                         serviceProviderDO) {
        HashMap<String, LinkedHashSet<String>> pairMap = new HashMap<>();
        addKeyValuePair(pairMap, ISSUER, serviceProviderDO.getIssuer());
        addKeyValuePair(pairMap, ISSUER_QUALIFIER, serviceProviderDO.getIssuerQualifier());
        for (String url : serviceProviderDO.getAssertionConsumerUrls()) {
            addKeyValuePair(pairMap, ASSERTION_CONSUMER_URLS, url);
        }
        addKeyValuePair(pairMap, DEFAULT_ASSERTION_CONSUMER_URL, serviceProviderDO.getDefaultAssertionConsumerUrl());
        addKeyValuePair(pairMap, SIGNING_ALGORITHM_URI, serviceProviderDO.getSigningAlgorithmUri());
        addKeyValuePair(pairMap, DIGEST_ALGORITHM_URI, serviceProviderDO.getDigestAlgorithmUri());
        addKeyValuePair(pairMap, ASSERTION_ENCRYPTION_ALGORITHM_URI,
                serviceProviderDO.getAssertionEncryptionAlgorithmUri());
        addKeyValuePair(pairMap, KEY_ENCRYPTION_ALGORITHM_URI, serviceProviderDO.getKeyEncryptionAlgorithmUri());
        addKeyValuePair(pairMap, CERT_ALIAS, serviceProviderDO.getCertAlias());
        addKeyValuePair(pairMap, ATTRIBUTE_CONSUMING_SERVICE_INDEX,
                serviceProviderDO.getAttributeConsumingServiceIndex());
        addKeyValuePair(pairMap, DO_SIGN_RESPONSE, serviceProviderDO.isDoSignResponse() ? "true" : "false");
        addKeyValuePair(pairMap, DO_SINGLE_LOGOUT, serviceProviderDO.isDoSingleLogout() ? "true" : "false");
        addKeyValuePair(pairMap, DO_FRONT_CHANNEL_LOGOUT,
                serviceProviderDO.isDoFrontChannelLogout() ? "true" : "false");
        addKeyValuePair(pairMap, FRONT_CHANNEL_LOGOUT_BINDING, serviceProviderDO.getFrontChannelLogoutBinding());
        addKeyValuePair(pairMap, IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                serviceProviderDO.isAssertionQueryRequestProfileEnabled() ? "true" : "false");
        addKeyValuePair(pairMap, SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                serviceProviderDO.getSupportedAssertionQueryRequestTypes());
        addKeyValuePair(pairMap, ENABLE_SAML2_ARTIFACT_BINDING,
                serviceProviderDO.isEnableSAML2ArtifactBinding() ? "true" : "false");
        addKeyValuePair(pairMap, DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                serviceProviderDO.isDoValidateSignatureInArtifactResolve() ? "true" : "false");
        addKeyValuePair(pairMap, LOGIN_PAGE_URL, serviceProviderDO.getLoginPageURL());
        addKeyValuePair(pairMap, SLO_RESPONSE_URL, serviceProviderDO.getSloResponseURL());
        addKeyValuePair(pairMap, SLO_REQUEST_URL, serviceProviderDO.getSloRequestURL());
        for (String claim : serviceProviderDO.getRequestedClaims()) {
            addKeyValuePair(pairMap, REQUESTED_CLAIMS, claim);
        }
        for (String audience : serviceProviderDO.getRequestedAudiences()) {
            addKeyValuePair(pairMap, REQUESTED_AUDIENCES, audience);
        }
        for (String recipient : serviceProviderDO.getRequestedRecipients()) {
            addKeyValuePair(pairMap, REQUESTED_RECIPIENTS, recipient);
        }
        addKeyValuePair(pairMap, ENABLE_ATTRIBUTES_BY_DEFAULT,
                serviceProviderDO.isEnableAttributesByDefault() ? "true" : "false");
        addKeyValuePair(pairMap, NAME_ID_CLAIM_URI, serviceProviderDO.getNameIdClaimUri());
        addKeyValuePair(pairMap, NAME_ID_FORMAT, serviceProviderDO.getNameIDFormat());
        addKeyValuePair(pairMap, IDP_INIT_SSO_ENABLED, serviceProviderDO.isIdPInitSSOEnabled() ? "true" : "false");
        addKeyValuePair(pairMap, IDP_INIT_SLO_ENABLED, serviceProviderDO.isIdPInitSLOEnabled() ? "true" : "false");
        for (String url : serviceProviderDO.getIdpInitSLOReturnToURLs()) {
            addKeyValuePair(pairMap, IDP_INIT_SLO_RETURN_TO_URLS, url);
        }
        addKeyValuePair(pairMap, DO_ENABLE_ENCRYPTED_ASSERTION,
                serviceProviderDO.isDoEnableEncryptedAssertion() ? "true" : "false");
        addKeyValuePair(pairMap, DO_VALIDATE_SIGNATURE_IN_REQUESTS,
                serviceProviderDO.isDoValidateSignatureInRequests() ? "true" : "false");
        addKeyValuePair(pairMap, IDP_ENTITY_ID_ALIAS, serviceProviderDO.getIdpEntityIDAlias());
        return pairMap;
    }

    private void addKeyValuePair(HashMap<String, LinkedHashSet<String>> map, String key, String value) {
        LinkedHashSet<String> values;
        if (map.containsKey(key)) {
            values = map.get(key);
        } else {
            values = new LinkedHashSet<>();
        }
        values.add(value);
        map.put(key, values);
    }

    private SAMLSSOServiceProviderDO updateServiceProviderDO(SAMLSSOServiceProviderDO samlssoServiceProviderDO,
                                                             String key, String value) {
        switch (key) {
            case ISSUER:
                samlssoServiceProviderDO.setIssuer(value);
                break;
            case ISSUER_QUALIFIER:
                samlssoServiceProviderDO.setIssuerQualifier(value);
                break;
            case ASSERTION_CONSUMER_URLS:
                String[] arr = samlssoServiceProviderDO.getAssertionConsumerUrls();
                ArrayList<String> list = new ArrayList<>(Arrays.asList(arr));
                list.add(value);
                samlssoServiceProviderDO.setAssertionConsumerUrls(list.toArray(new String[0]));
                break;
            case DEFAULT_ASSERTION_CONSUMER_URL:
                samlssoServiceProviderDO.setDefaultAssertionConsumerUrl(value);
                break;
            case SIGNING_ALGORITHM_URI:
                samlssoServiceProviderDO.setSigningAlgorithmUri(value);
                break;
            case DIGEST_ALGORITHM_URI:
                samlssoServiceProviderDO.setDigestAlgorithmUri(value);
                break;
            case ASSERTION_ENCRYPTION_ALGORITHM_URI:
                samlssoServiceProviderDO.setAssertionEncryptionAlgorithmUri(value);
                break;
            case KEY_ENCRYPTION_ALGORITHM_URI:
                samlssoServiceProviderDO.setKeyEncryptionAlgorithmUri(value);
                break;
            case CERT_ALIAS:
                samlssoServiceProviderDO.setCertAlias(value);
                break;
            case ATTRIBUTE_CONSUMING_SERVICE_INDEX:
                samlssoServiceProviderDO.setAttributeConsumingServiceIndex(value);
                break;
            case DO_SIGN_RESPONSE:
                samlssoServiceProviderDO.setDoSignResponse(value.equals("true"));
                break;
            case DO_SINGLE_LOGOUT:
                samlssoServiceProviderDO.setDoSingleLogout(value.equals("true"));
                break;
            case DO_FRONT_CHANNEL_LOGOUT:
                samlssoServiceProviderDO.setDoFrontChannelLogout(value.equals("true"));
                break;
            case FRONT_CHANNEL_LOGOUT_BINDING:
                samlssoServiceProviderDO.setFrontChannelLogoutBinding(value);
                break;
            case IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED:
                samlssoServiceProviderDO.setAssertionQueryRequestProfileEnabled(value.equals("true"));
                break;
            case SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES:
                samlssoServiceProviderDO.setSupportedAssertionQueryRequestTypes(value);
                break;
            case ENABLE_SAML2_ARTIFACT_BINDING:
                samlssoServiceProviderDO.setEnableSAML2ArtifactBinding(value.equals("true"));
                break;
            case DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE:
                samlssoServiceProviderDO.setDoValidateSignatureInArtifactResolve(value.equals("true"));
                break;
            case LOGIN_PAGE_URL:
                if (value == null || value.equals("null")) {
                    samlssoServiceProviderDO.setLoginPageURL("");
                } else {
                    samlssoServiceProviderDO.setLoginPageURL(value);
                }
                break;
            case SLO_RESPONSE_URL:
                samlssoServiceProviderDO.setSloResponseURL(value);
                break;
            case SLO_REQUEST_URL:
                samlssoServiceProviderDO.setSloRequestURL(value);
                break;
            case REQUESTED_CLAIMS:
                String[] requestedClaimsArray = samlssoServiceProviderDO.getRequestedClaims();
                ArrayList<String> requestedClaimsList = new ArrayList<>(Arrays.asList(requestedClaimsArray));
                requestedClaimsList.add(value);
                samlssoServiceProviderDO.setAssertionConsumerUrls(requestedClaimsList.toArray(new String[0]));
                break;
            case REQUESTED_AUDIENCES:
                String[] requestedAudiencesArray = samlssoServiceProviderDO.getRequestedAudiences();
                ArrayList<String> requestedAudiencesList = new ArrayList<>(Arrays.asList(requestedAudiencesArray));
                requestedAudiencesList.add(value);
                samlssoServiceProviderDO.setAssertionConsumerUrls(requestedAudiencesList.toArray(new String[0]));
                break;
            case REQUESTED_RECIPIENTS:
                String[] requestedRecipientsArray = samlssoServiceProviderDO.getRequestedRecipients();
                ArrayList<String> requestedRecipientsList = new ArrayList<>(Arrays.asList(requestedRecipientsArray));
                requestedRecipientsList.add(value);
                samlssoServiceProviderDO.setAssertionConsumerUrls(requestedRecipientsList.toArray(new String[0]));
                break;
            case ENABLE_ATTRIBUTES_BY_DEFAULT:
                samlssoServiceProviderDO.setEnableAttributesByDefault(value.equals("true"));
                break;
            case NAME_ID_CLAIM_URI:
                samlssoServiceProviderDO.setNameIdClaimUri(value);
                break;
            case NAME_ID_FORMAT:
                samlssoServiceProviderDO.setNameIDFormat(value);
                if (samlssoServiceProviderDO.getNameIDFormat() == null) {
                    samlssoServiceProviderDO.setNameIDFormat(NameIdentifier.EMAIL);
                }
                samlssoServiceProviderDO.setNameIDFormat(samlssoServiceProviderDO.getNameIDFormat().replace(":", "/"));
                break;
            case IDP_INIT_SSO_ENABLED:
                samlssoServiceProviderDO.setIdPInitSSOEnabled(value.equals("true"));
                break;
            case IDP_INIT_SLO_ENABLED:
                samlssoServiceProviderDO.setIdPInitSLOEnabled(value.equals("true"));
                break;
            case IDP_INIT_SLO_RETURN_TO_URLS:
                String[] idpInitSLOReturnToURLsArray = samlssoServiceProviderDO.getIdpInitSLOReturnToURLs();
                ArrayList<String> idpInitSLOReturnToURLsList =
                        new ArrayList<>(Arrays.asList(idpInitSLOReturnToURLsArray));
                idpInitSLOReturnToURLsList.add(value);
                samlssoServiceProviderDO.setAssertionConsumerUrls(idpInitSLOReturnToURLsList.toArray(new String[0]));
                break;
            case DO_ENABLE_ENCRYPTED_ASSERTION:
                samlssoServiceProviderDO.setDoEnableEncryptedAssertion(value.equals("true"));
                break;
            case DO_VALIDATE_SIGNATURE_IN_REQUESTS:
                samlssoServiceProviderDO.setDoValidateSignatureInRequests(value.equals("true"));
                break;
            case IDP_ENTITY_ID_ALIAS:
                samlssoServiceProviderDO.setIdpEntityIDAlias(value);
                break;
        }
        return samlssoServiceProviderDO;
    }


}