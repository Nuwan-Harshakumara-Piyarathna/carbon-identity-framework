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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
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
import org.wso2.carbon.identity.core.model.SAMLSSOAttribute;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.utils.Transaction;
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
import java.util.List;

import static org.wso2.carbon.identity.core.util.JdbcUtils.isH2DB;

public class SAMLSSOServiceProviderDAO extends AbstractDAO<SAMLSSOServiceProviderDO> {

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

    public SAMLSSOServiceProviderDAO(Registry registry) {
        this.registry = registry;
    }

    protected SAMLSSOServiceProviderDO resourceToObject(Resource resource) {
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();
        serviceProviderDO.setIssuer(resource
                .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER));
        serviceProviderDO.setAssertionConsumerUrls(resource.getPropertyValues(
                IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_CONS_URLS));
        serviceProviderDO.setDefaultAssertionConsumerUrl(resource.getProperty(
                IdentityRegistryResources.PROP_DEFAULT_SAML_SSO_ASSERTION_CONS_URL));
        serviceProviderDO.setCertAlias(resource
                .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_CERT_ALIAS));

        if (StringUtils.isNotEmpty(resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_SIGNING_ALGORITHM))) {
            serviceProviderDO.setSigningAlgorithmUri(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SSO_SIGNING_ALGORITHM));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED) !=
                null) {
            serviceProviderDO.setAssertionQueryRequestProfileEnabled(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED).trim()));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES) !=
                null) {
            serviceProviderDO.setSupportedAssertionQueryRequestTypes(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES).trim());
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_SAML2_ARTIFACT_BINDING) !=
                null) {
            serviceProviderDO.setEnableSAML2ArtifactBinding(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_SAML2_ARTIFACT_BINDING).trim()));
        }

        if (StringUtils.isNotEmpty(resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_DIGEST_ALGORITHM))) {
            serviceProviderDO.setDigestAlgorithmUri(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SSO_DIGEST_ALGORITHM));
        }

        if (StringUtils.isNotEmpty(resource.getProperty(IdentityRegistryResources
                .PROP_SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM))) {
            serviceProviderDO.setAssertionEncryptionAlgorithmUri(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM));
        }

        if (StringUtils.isNotEmpty(resource.getProperty(IdentityRegistryResources
                .PROP_SAML_SSO_KEY_ENCRYPTION_ALGORITHM))) {
            serviceProviderDO.setKeyEncryptionAlgorithmUri(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SSO_KEY_ENCRYPTION_ALGORITHM));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_SINGLE_LOGOUT) != null) {
            serviceProviderDO.setDoSingleLogout(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_DO_SINGLE_LOGOUT).trim()));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_NAMEID_FORMAT) != null) {
            serviceProviderDO.setNameIDFormat(resource.
                    getProperty(IdentityRegistryResources.PROP_SAML_SSO_NAMEID_FORMAT));
        }

        if (resource
                .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI) != null) {
            if (Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI).trim())) {
                serviceProviderDO.setNameIdClaimUri(resource.
                        getProperty(IdentityRegistryResources.PROP_SAML_SSO_NAMEID_CLAIMURI));
            }
        }

        serviceProviderDO.setLoginPageURL(resource.
                getProperty(IdentityRegistryResources.PROP_SAML_SSO_LOGIN_PAGE_URL));

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_RESPONSE) != null) {
            serviceProviderDO.setDoSignResponse(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_RESPONSE).trim()));
        }

        if (serviceProviderDO.isDoSingleLogout()) {
            serviceProviderDO.setSloResponseURL(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SLO_RESPONSE_URL));
            serviceProviderDO.setSloRequestURL(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SLO_REQUEST_URL));
            // Check front channel logout enable.
            if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_FRONT_CHANNEL_LOGOUT) != null) {
                serviceProviderDO.setDoFrontChannelLogout(Boolean.valueOf(resource.getProperty(
                        IdentityRegistryResources.PROP_SAML_SSO_DO_FRONT_CHANNEL_LOGOUT).trim()));
                if (serviceProviderDO.isDoFrontChannelLogout()) {
                    if (resource.getProperty(IdentityRegistryResources.
                            PROP_SAML_SSO_FRONT_CHANNEL_LOGOUT_BINDING) != null) {
                        serviceProviderDO.setFrontChannelLogoutBinding(resource.getProperty(
                                IdentityRegistryResources.PROP_SAML_SSO_FRONT_CHANNEL_LOGOUT_BINDING));
                    } else {
                        // Default is redirect-binding.
                        serviceProviderDO.setFrontChannelLogoutBinding(IdentityRegistryResources
                                .DEFAULT_FRONT_CHANNEL_LOGOUT_BINDING);
                    }

                }
            }
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_ASSERTIONS) != null) {
            serviceProviderDO.setDoSignAssertions(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_ASSERTIONS).trim()));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_ENABLE_ECP) != null) {
            serviceProviderDO.setSamlECP(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_ENABLE_ECP).trim()));
        }

        if (resource
                .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ATTRIB_CONSUMING_SERVICE_INDEX) != null) {
            serviceProviderDO
                    .setAttributeConsumingServiceIndex(resource
                            .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ATTRIB_CONSUMING_SERVICE_INDEX));
        } else {
            // Specific DB's (like oracle) returns empty strings as null.
            serviceProviderDO.setAttributeConsumingServiceIndex("");
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_CLAIMS) != null) {
            serviceProviderDO.setRequestedClaims(resource
                    .getPropertyValues(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_CLAIMS));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_AUDIENCES) != null) {
            serviceProviderDO.setRequestedAudiences(resource
                    .getPropertyValues(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_AUDIENCES));
        }

        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_RECIPIENTS) != null) {
            serviceProviderDO.setRequestedRecipients(resource
                    .getPropertyValues(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_RECIPIENTS));
        }

        if (resource
                .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ATTRIBUTES_BY_DEFAULT) != null) {
            String enableAttrByDefault = resource
                    .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ATTRIBUTES_BY_DEFAULT);
            serviceProviderDO.setEnableAttributesByDefault(Boolean.valueOf(enableAttrByDefault));
        }
        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_IDP_INIT_SSO_ENABLED) != null) {
            serviceProviderDO.setIdPInitSSOEnabled(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_IDP_INIT_SSO_ENABLED).trim()));
        }
        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SLO_IDP_INIT_SLO_ENABLED) != null) {
            serviceProviderDO.setIdPInitSLOEnabled(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SLO_IDP_INIT_SLO_ENABLED).trim()));
            if (serviceProviderDO.isIdPInitSLOEnabled() && resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_IDP_INIT_SLO_RETURN_URLS) != null) {
                serviceProviderDO.setIdpInitSLOReturnToURLs(resource.getPropertyValues(
                        IdentityRegistryResources.PROP_SAML_IDP_INIT_SLO_RETURN_URLS));
            }
        }
        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ENCRYPTED_ASSERTION) != null) {
            serviceProviderDO.setDoEnableEncryptedAssertion(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ENCRYPTED_ASSERTION).trim()));
        }
        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_REQUESTS) != null) {
            serviceProviderDO.setDoValidateSignatureInRequests(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_REQUESTS).trim()));
        }
        if (resource.getProperty(
                IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE) != null) {
            serviceProviderDO.setDoValidateSignatureInArtifactResolve(Boolean.valueOf(resource.getProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE).trim()));
        }
        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_QUALIFIER) != null) {
            serviceProviderDO.setIssuerQualifier(resource
                    .getProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_QUALIFIER));
        }
        if (resource.getProperty(IdentityRegistryResources.PROP_SAML_SSO_IDP_ENTITY_ID_ALIAS) != null) {
            serviceProviderDO.setIdpEntityIDAlias(resource.getProperty(IdentityRegistryResources
                    .PROP_SAML_SSO_IDP_ENTITY_ID_ALIAS));
        }
        return serviceProviderDO;
    }

    /**
     * Add the service provider information to the registry.
     * @param serviceProviderDO Service provider information object.
     * @return True if addition successful.
     * @throws IdentityException Error while persisting to the registry.
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

        String path = IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS + encodePath(serviceProviderDO.getIssuer());

        boolean isTransactionStarted = Transaction.isStarted();
        boolean isErrorOccurred = false;
        try {
            if (registry.resourceExists(path)) {
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

            Resource resource = createResource(serviceProviderDO);
            if (!isTransactionStarted) {
                registry.beginTransaction();
            }
            registry.put(path, resource);
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                    log.debug("SAML2 Service Provider " + serviceProviderDO.getIssuer() + " with issuer "
                            + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier " +
                            serviceProviderDO.getIssuerQualifier() + " is added successfully.");
                } else {
                    log.debug("SAML2 Service Provider " + serviceProviderDO.getIssuer() + " is added successfully.");
                }
            }
            return true;
        } catch (RegistryException e) {
            isErrorOccurred = true;
            String msg;
            if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                msg = "Error while adding SAML2 Service Provider for issuer: " + getIssuerWithoutQualifier
                        (serviceProviderDO.getIssuer()) + " and qualifier name " + serviceProviderDO
                        .getIssuerQualifier();
            } else {
                msg = "Error while adding SAML2 Service Provider for issuer: " + serviceProviderDO.getIssuer();
            }
            log.error(msg, e);
            throw IdentityException.error(msg, e);
        } finally {
            commitOrRollbackTransaction(isErrorOccurred);
        }
    }

    public boolean addServiceProvider_new(SAMLSSOServiceProviderDO serviceProviderDO) throws IdentityException {

        if (serviceProviderDO == null || serviceProviderDO.getIssuer() == null ||
                StringUtils.isBlank(serviceProviderDO.getIssuer())) {
            throw new IdentityException("Issuer cannot be found in the provided arguments.");
        }

        // If an issuer qualifier value is specified, it is appended to the end of the issuer value.
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(getIssuerWithQualifier(serviceProviderDO.getIssuer(),
                    serviceProviderDO.getIssuerQualifier()));
        }

        return true;
    }

    private Resource createResource(SAMLSSOServiceProviderDO serviceProviderDO) throws RegistryException {
        Resource resource;
        resource = registry.newResource();
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER,
                serviceProviderDO.getIssuer());
        resource.setProperty(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_CONS_URLS,
                serviceProviderDO.getAssertionConsumerUrlList());
        resource.addProperty(IdentityRegistryResources.PROP_DEFAULT_SAML_SSO_ASSERTION_CONS_URL,
                serviceProviderDO.getDefaultAssertionConsumerUrl());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_CERT_ALIAS,
                serviceProviderDO.getCertAlias());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_LOGIN_PAGE_URL,
                serviceProviderDO.getLoginPageURL());
        resource.addProperty(
                IdentityRegistryResources.PROP_SAML_SSO_NAMEID_FORMAT,
                serviceProviderDO.getNameIDFormat());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_SIGNING_ALGORITHM, serviceProviderDO
                .getSigningAlgorithmUri());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_DIGEST_ALGORITHM, serviceProviderDO
                .getDigestAlgorithmUri());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM, serviceProviderDO
                .getAssertionEncryptionAlgorithmUri());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_KEY_ENCRYPTION_ALGORITHM, serviceProviderDO
                .getKeyEncryptionAlgorithmUri());
        if (serviceProviderDO.getNameIdClaimUri() != null
                && serviceProviderDO.getNameIdClaimUri().trim().length() > 0) {
            resource.addProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI,
                    "true");
            resource.addProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_NAMEID_CLAIMURI,
                    serviceProviderDO.getNameIdClaimUri());
        } else {
            resource.addProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI,
                    "false");
        }

        String doSingleLogout = String.valueOf(serviceProviderDO.isDoSingleLogout());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_SINGLE_LOGOUT, doSingleLogout);
        if (serviceProviderDO.isDoSingleLogout()) {
            if (StringUtils.isNotBlank(serviceProviderDO.getSloResponseURL())) {
                resource.addProperty(IdentityRegistryResources.PROP_SAML_SLO_RESPONSE_URL,
                        serviceProviderDO.getSloResponseURL());
            }
            if (StringUtils.isNotBlank(serviceProviderDO.getSloRequestURL())) {
                resource.addProperty(IdentityRegistryResources.PROP_SAML_SLO_REQUEST_URL,
                        serviceProviderDO.getSloRequestURL());
            }
            // Create doFrontChannelLogout property in the registry.
            String doFrontChannelLogout = String.valueOf(serviceProviderDO.isDoFrontChannelLogout());
            resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_FRONT_CHANNEL_LOGOUT, doFrontChannelLogout);
            if (serviceProviderDO.isDoFrontChannelLogout()) {
                // Create frontChannelLogoutMethod property in the registry.
                resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_FRONT_CHANNEL_LOGOUT_BINDING,
                        serviceProviderDO.getFrontChannelLogoutBinding());
            }
        }

        String doSignResponse = String.valueOf(serviceProviderDO.isDoSignResponse());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_RESPONSE,
                doSignResponse);
        String isAssertionQueryRequestProfileEnabled = String.valueOf(serviceProviderDO
                .isAssertionQueryRequestProfileEnabled());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                isAssertionQueryRequestProfileEnabled);
        String supportedAssertionQueryRequestTypes = serviceProviderDO.getSupportedAssertionQueryRequestTypes();
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                supportedAssertionQueryRequestTypes);
        String isEnableSAML2ArtifactBinding = String.valueOf(serviceProviderDO
                .isEnableSAML2ArtifactBinding());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_SAML2_ARTIFACT_BINDING,
                isEnableSAML2ArtifactBinding);
        String doSignAssertions = String.valueOf(serviceProviderDO.isDoSignAssertions());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_ASSERTIONS,
                doSignAssertions);
        String isSamlECP = String.valueOf(serviceProviderDO.isSamlECP());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_ENABLE_ECP,
                isSamlECP);
        if (CollectionUtils.isNotEmpty(serviceProviderDO.getRequestedClaimsList())) {
            resource.setProperty(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_CLAIMS,
                    serviceProviderDO.getRequestedClaimsList());
        }
        if (serviceProviderDO.getAttributeConsumingServiceIndex() != null) {
            resource.addProperty(
                    IdentityRegistryResources.PROP_SAML_SSO_ATTRIB_CONSUMING_SERVICE_INDEX,
                    serviceProviderDO.getAttributeConsumingServiceIndex());
        }
        if (CollectionUtils.isNotEmpty(serviceProviderDO.getRequestedAudiencesList())) {
            resource.setProperty(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_AUDIENCES,
                    serviceProviderDO.getRequestedAudiencesList());
        }
        if (CollectionUtils.isNotEmpty(serviceProviderDO.getRequestedRecipientsList())) {
            resource.setProperty(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_RECIPIENTS,
                    serviceProviderDO.getRequestedRecipientsList());
        }

        String enableAttributesByDefault = String.valueOf(serviceProviderDO.isEnableAttributesByDefault());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ATTRIBUTES_BY_DEFAULT,
                enableAttributesByDefault);
        String idPInitSSOEnabled = String.valueOf(serviceProviderDO.isIdPInitSSOEnabled());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_IDP_INIT_SSO_ENABLED,
                idPInitSSOEnabled);
        String idPInitSLOEnabled = String.valueOf(serviceProviderDO.isIdPInitSLOEnabled());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SLO_IDP_INIT_SLO_ENABLED, idPInitSLOEnabled);
        if (serviceProviderDO.isIdPInitSLOEnabled() && serviceProviderDO.getIdpInitSLOReturnToURLList().size() > 0) {
            resource.setProperty(IdentityRegistryResources.PROP_SAML_IDP_INIT_SLO_RETURN_URLS,
                    serviceProviderDO.getIdpInitSLOReturnToURLList());
        }
        String enableEncryptedAssertion = String.valueOf(serviceProviderDO.isDoEnableEncryptedAssertion());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ENCRYPTED_ASSERTION,
                enableEncryptedAssertion);

        String validateSignatureInRequests = String.valueOf(serviceProviderDO.isDoValidateSignatureInRequests());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_REQUESTS,
                validateSignatureInRequests);

        String validateSignatureInArtifactResolve =
                String.valueOf(serviceProviderDO.isDoValidateSignatureInArtifactResolve());
        resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                validateSignatureInArtifactResolve);
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_QUALIFIER, serviceProviderDO
                    .getIssuerQualifier());
        }
        if (StringUtils.isNotBlank(serviceProviderDO.getIdpEntityIDAlias())) {
            resource.addProperty(IdentityRegistryResources.PROP_SAML_SSO_IDP_ENTITY_ID_ALIAS, serviceProviderDO
                    .getIdpEntityIDAlias());
        }
        return resource;
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
        List<SAMLSSOServiceProviderDO> serviceProvidersList = new ArrayList<>();
        try {
            if (registry.resourceExists(IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS)) {
                Resource samlSSOServiceProvidersResource = registry.get(IdentityRegistryResources
                        .SAML_SSO_SERVICE_PROVIDERS);
                if (samlSSOServiceProvidersResource instanceof Collection) {
                    Collection samlSSOServiceProvidersCollection = (Collection) samlSSOServiceProvidersResource;
                    String[] resources = samlSSOServiceProvidersCollection.getChildren();
                    for (String resource : resources) {
                        getChildResources(resource, serviceProvidersList);
                    }
                }
            }
        } catch (RegistryException e) {
            log.error("Error reading Service Providers from Registry", e);
            throw IdentityException.error("Error reading Service Providers from Registry", e);
        }
        return serviceProvidersList.toArray(new SAMLSSOServiceProviderDO[serviceProvidersList.size()]);
    }

    /**
     * Remove the service provider with the given name.
     * @return True if deletion success.
     * @param issuer Name of the SAML issuer.
     * @throws IdentityException Error occurred while removing the SAML service provider from registry.
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        if (issuer == null || StringUtils.isEmpty(issuer.trim())) {
            throw new IllegalArgumentException("Trying to delete issuer \'" + issuer + "\'");
        }

        String path = IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS + encodePath(issuer);
        boolean isTransactionStarted = Transaction.isStarted();
        boolean isErrorOccurred = false;
        try {
            if (!registry.resourceExists(path)) {
                if (log.isDebugEnabled()) {
                    log.debug("Registry resource does not exist for the path: " + path);
                }
                return false;
            }

            // Since we are getting a global registry object, better to check whether this is a task inside already
            // started transaction.
            if (!isTransactionStarted) {
                registry.beginTransaction();
            }
            registry.delete(path);
            return true;
        } catch (RegistryException e) {
            isErrorOccurred = true;
            String msg = "Error removing the service provider from the registry with name: " + issuer;
            log.error(msg, e);
            throw IdentityException.error(msg, e);
        } finally {
            commitOrRollbackTransaction(isErrorOccurred);
        }
    }

    /**
     * Get the service provider.
     *
     * @param issuer
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer) throws IdentityException {

        String path = IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS + encodePath(issuer);
        SAMLSSOServiceProviderDO serviceProviderDO = null;

        UserRegistry userRegistry = null;
        String tenantDomain = null;
        try {
            userRegistry = (UserRegistry) registry;
            tenantDomain = IdentityTenantUtil.getRealmService().getTenantManager().getDomain(userRegistry.
                    getTenantId());
            if (registry.resourceExists(path)) {
                serviceProviderDO = resourceToObject(registry.get(path));

                // Load the certificate stored in the database, if signature validation is enabled..
                if (serviceProviderDO.isDoValidateSignatureInRequests() ||
                        serviceProviderDO.isDoValidateSignatureInArtifactResolve() ||
                        serviceProviderDO.isDoEnableEncryptedAssertion()) {
                    Tenant tenant = new Tenant();
                    tenant.setDomain(tenantDomain);
                    tenant.setId(userRegistry.getTenantId());

                    serviceProviderDO.setX509Certificate(getApplicationCertificate(serviceProviderDO, tenant));
                }
                serviceProviderDO.setTenantDomain(tenantDomain);
            }
        } catch (RegistryException e) {
            throw IdentityException.error("Error occurred while checking if resource path \'" + path + "\' exists in " +
                    "registry for tenant domain : " + tenantDomain, e);
        } catch (UserStoreException e) {
            throw IdentityException.error("Error occurred while getting tenant domain from tenant ID : " +
                    userRegistry.getTenantId(), e);
        } catch (SQLException e) {
            throw IdentityException.error(String.format("An error occurred while getting the " +
                    "application certificate id for validating the requests from the issuer '%s'", issuer), e);
        } catch (CertificateRetrievingException e) {
            throw IdentityException.error(String.format("An error occurred while getting the " +
                    "application certificate for validating the requests from the issuer '%s'", issuer), e);
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
        String path = IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS + encodePath(issuer);
        try {
            return registry.resourceExists(path);
        } catch (RegistryException e) {
            throw IdentityException.error("Error occurred while checking if resource path \'" + path + "\' exists in " +
                    "registry");
        }
    }

    private String encodePath(String path) {
        String encodedStr = new String(Base64.encodeBase64(path.getBytes()));
        return encodedStr.replace("=", "");
    }

    /**
     * Upload service Provider using metadata file..
     * @param serviceProviderDO Service provider information object.
     * @return True if upload success.
     * @throws IdentityException Error occurred while adding the information to registry.
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

        String path = IdentityRegistryResources.SAML_SSO_SERVICE_PROVIDERS + encodePath(serviceProviderDO.getIssuer());

        boolean isTransactionStarted = Transaction.isStarted();
        boolean isErrorOccurred = false;
        try {
            if (registry.resourceExists(path)) {
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

            if (!isTransactionStarted) {
                registry.beginTransaction();
            }

            Resource resource = createResource(serviceProviderDO);
            registry.put(path, resource);
            if (log.isDebugEnabled()) {
                if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
                    log.debug("SAML2 Service Provider " + serviceProviderDO.getIssuer() + " with issuer "
                            + getIssuerWithoutQualifier(serviceProviderDO.getIssuer()) + " and qualifier " +
                            serviceProviderDO.getIssuerQualifier() + " is added successfully.");
                } else {
                    log.debug("SAML2 Service Provider " + serviceProviderDO.getIssuer() + " is added successfully.");
                }
            }
            return serviceProviderDO;
        } catch (RegistryException e) {
            isErrorOccurred = true;
            throw IdentityException.error("Error while adding Service Provider.", e);
        } finally {
            commitOrRollbackTransaction(isErrorOccurred);
        }
    }

    /**
     * Commit or rollback the registry operation depends on the error condition.
     * @param isErrorOccurred Identifier for error transactions.
     * @throws IdentityException Error while committing or running rollback on the transaction.
     */
    private void commitOrRollbackTransaction(boolean isErrorOccurred) throws IdentityException {

        try {
            // Rollback the transaction if there is an error, Otherwise try to commit.
            if (isErrorOccurred) {
                registry.rollbackTransaction();
            } else {
                registry.commitTransaction();
            }
        } catch (RegistryException ex) {
            throw new IdentityException("Error occurred while trying to commit or rollback the registry operation.", ex);
        }
    }

    /**
     * This helps to find resources in a recursive manner.
     *
     * @param parentResource      parent resource Name.
     * @param serviceProviderList child resource list.
     * @throws RegistryException
     */
    private void getChildResources(String parentResource, List<SAMLSSOServiceProviderDO>
            serviceProviderList) throws RegistryException {

        if (registry.resourceExists(parentResource)) {
            Resource resource = registry.get(parentResource);
            if (resource instanceof Collection) {
                Collection collection = (Collection) resource;
                String[] resources = collection.getChildren();
                for (String res : resources) {
                    getChildResources(res, serviceProviderList);
                }
            } else {
                serviceProviderList.add(resourceToObject(resource));
            }
        }
    }

    public List<SAMLSSOAttribute> convertServiceProviderToList(SAMLSSOServiceProviderDO serviceProviderDO) {
        UserRegistry userRegistry = (UserRegistry) registry;
        int tenantId = userRegistry.getTenantId();
        List<SAMLSSOAttribute> list = new ArrayList<>();
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ISSUER,serviceProviderDO.getIssuer(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ISSUER_QUALIFIER,serviceProviderDO.getIssuerQualifier(),tenantId));
        for(String url : serviceProviderDO.getAssertionConsumerUrls()){
            list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ASSERTION_CONSUMER_URLS,url,tenantId));
        }
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DEFAULT_ASSERTION_CONSUMER_URL,serviceProviderDO.getDefaultAssertionConsumerUrl(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),SIGNING_ALGORITHM_URI,serviceProviderDO.getSigningAlgorithmUri(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DIGEST_ALGORITHM_URI,serviceProviderDO.getDigestAlgorithmUri(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ASSERTION_ENCRYPTION_ALGORITHM_URI,serviceProviderDO.getAssertionEncryptionAlgorithmUri(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),KEY_ENCRYPTION_ALGORITHM_URI,serviceProviderDO.getKeyEncryptionAlgorithmUri(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),CERT_ALIAS,serviceProviderDO.getCertAlias(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ATTRIBUTE_CONSUMING_SERVICE_INDEX,serviceProviderDO.getAttributeConsumingServiceIndex(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DO_SIGN_RESPONSE,serviceProviderDO.isDoSignResponse() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DO_SINGLE_LOGOUT,serviceProviderDO.isDoSingleLogout() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DO_FRONT_CHANNEL_LOGOUT,serviceProviderDO.isDoFrontChannelLogout() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),FRONT_CHANNEL_LOGOUT_BINDING,serviceProviderDO.getFrontChannelLogoutBinding(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,serviceProviderDO.isAssertionQueryRequestProfileEnabled() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,serviceProviderDO.getSupportedAssertionQueryRequestTypes(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ENABLE_SAML2_ARTIFACT_BINDING,serviceProviderDO.isEnableSAML2ArtifactBinding() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,serviceProviderDO.isDoValidateSignatureInArtifactResolve() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),LOGIN_PAGE_URL,serviceProviderDO.getLoginPageURL(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),SLO_RESPONSE_URL,serviceProviderDO.getSloResponseURL(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),SLO_REQUEST_URL,serviceProviderDO.getSloRequestURL(),tenantId));
        for(String claim : serviceProviderDO.getRequestedClaims()){
            list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),REQUESTED_CLAIMS,claim,tenantId));
        }
        for(String audience : serviceProviderDO.getRequestedAudiences()){
            list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),REQUESTED_AUDIENCES,audience,tenantId));
        }
        for(String recipient : serviceProviderDO.getRequestedRecipients()){
            list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),REQUESTED_RECIPIENTS,recipient,tenantId));
        }
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),ENABLE_ATTRIBUTES_BY_DEFAULT,serviceProviderDO.isEnableAttributesByDefault() ? "true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),NAME_ID_CLAIM_URI,serviceProviderDO.getNameIdClaimUri(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),NAME_ID_FORMAT,serviceProviderDO.getNameIDFormat(),tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),IDP_INIT_SSO_ENABLED,serviceProviderDO.isIdPInitSSOEnabled()?"true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),IDP_INIT_SLO_ENABLED,serviceProviderDO.isIdPInitSLOEnabled()?"true":"false",tenantId));
        for(String url : serviceProviderDO.getIdpInitSLOReturnToURLs()){
            list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),IDP_INIT_SLO_RETURN_TO_URLS,url,tenantId));
        }
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DO_ENABLE_ENCRYPTED_ASSERTION,serviceProviderDO.isDoEnableEncryptedAssertion()?"true":"false",tenantId));
        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),DO_VALIDATE_SIGNATURE_IN_REQUESTS,serviceProviderDO.isDoValidateSignatureInRequests()?"true":"false",tenantId));

        list.add(new SAMLSSOAttribute(serviceProviderDO.getIssuer(),IDP_ENTITY_ID_ALIAS,serviceProviderDO.getIdpEntityIDAlias(),tenantId));
        return list;
    }

    private SAMLSSOServiceProviderDO updateServiceProviderDO(SAMLSSOServiceProviderDO samlssoServiceProviderDO, SAMLSSOAttribute item) {
        switch (item.getProp_key()){
            case ISSUER:
                samlssoServiceProviderDO.setIssuer(item.getProp_value());
                break;
            case ISSUER_QUALIFIER:
                samlssoServiceProviderDO.setIssuerQualifier(item.getProp_value());
                break;
            case ASSERTION_CONSUMER_URLS:
                String[] arr = samlssoServiceProviderDO.getAssertionConsumerUrls();
                ArrayList<String> list = new ArrayList<>(Arrays.asList(arr));
                list.add(item.getProp_value());
                samlssoServiceProviderDO.setAssertionConsumerUrls(list.toArray(new String[0]));
                break;
            case DEFAULT_ASSERTION_CONSUMER_URL:
                samlssoServiceProviderDO.setDefaultAssertionConsumerUrl(item.getProp_value());
                break;
            case SIGNING_ALGORITHM_URI:
                samlssoServiceProviderDO.setSigningAlgorithmUri(item.getProp_value());
                break;
            case DIGEST_ALGORITHM_URI:
                samlssoServiceProviderDO.setDigestAlgorithmUri(item.getProp_value());
                break;
            case ASSERTION_ENCRYPTION_ALGORITHM_URI:
                samlssoServiceProviderDO.setAssertionEncryptionAlgorithmUri(item.getProp_value());
                break;
            case KEY_ENCRYPTION_ALGORITHM_URI:
                samlssoServiceProviderDO.setKeyEncryptionAlgorithmUri(item.getProp_value());
                break;
            case CERT_ALIAS:
                samlssoServiceProviderDO.setCertAlias(item.getProp_value());
                break;
            case ATTRIBUTE_CONSUMING_SERVICE_INDEX:
                samlssoServiceProviderDO.setAttributeConsumingServiceIndex(item.getProp_value());
                break;
            case DO_SIGN_RESPONSE:
                samlssoServiceProviderDO.setDoSignResponse(item.getProp_value().equals("true"));
                break;
            case DO_SINGLE_LOGOUT:
                samlssoServiceProviderDO.setDoSingleLogout(item.getProp_value().equals("true"));
                break;
            case DO_FRONT_CHANNEL_LOGOUT:
                samlssoServiceProviderDO.setDoFrontChannelLogout(item.getProp_value().equals("true"));
                break;
            case FRONT_CHANNEL_LOGOUT_BINDING:
                samlssoServiceProviderDO.setFrontChannelLogoutBinding(item.getProp_value());
                break;
            case IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED:
                samlssoServiceProviderDO.setAssertionQueryRequestProfileEnabled(item.getProp_value().equals("true"));
                break;
            case SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES:
                samlssoServiceProviderDO.setSupportedAssertionQueryRequestTypes(item.getProp_value());
                break;
            case ENABLE_SAML2_ARTIFACT_BINDING:
                samlssoServiceProviderDO.setEnableSAML2ArtifactBinding(item.getProp_value().equals("true"));
                break;
            case DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE:
                samlssoServiceProviderDO.setDoValidateSignatureInArtifactResolve(item.getProp_value().equals("true"));
                break;
            case LOGIN_PAGE_URL:
                if(item.getProp_value() == null || item.getProp_value().equals("null")){
                    samlssoServiceProviderDO.setLoginPageURL("");
                }
                else{
                    samlssoServiceProviderDO.setLoginPageURL(item.getProp_value());
                }
                break;
            case SLO_RESPONSE_URL:
                samlssoServiceProviderDO.setSloResponseURL(item.getProp_value());
                break;
            case SLO_REQUEST_URL:
                samlssoServiceProviderDO.setSloRequestURL(item.getProp_value());
                break;
            case REQUESTED_CLAIMS:
                String[] requestedClaimsArray = samlssoServiceProviderDO.getRequestedClaims();
                ArrayList<String> requestedClaimsList = new ArrayList<>(Arrays.asList(requestedClaimsArray));
                requestedClaimsList.add(item.getProp_value());
                samlssoServiceProviderDO.setAssertionConsumerUrls(requestedClaimsList.toArray(new String[0]));
                break;
            case REQUESTED_AUDIENCES:
                String[] requestedAudiencesArray = samlssoServiceProviderDO.getRequestedAudiences();
                ArrayList<String> requestedAudiencesList = new ArrayList<>(Arrays.asList(requestedAudiencesArray));
                requestedAudiencesList.add(item.getProp_value());
                samlssoServiceProviderDO.setAssertionConsumerUrls(requestedAudiencesList.toArray(new String[0]));
                break;
            case REQUESTED_RECIPIENTS:
                String[] requestedRecipientsArray = samlssoServiceProviderDO.getRequestedRecipients();
                ArrayList<String> requestedRecipientsList = new ArrayList<>(Arrays.asList(requestedRecipientsArray));
                requestedRecipientsList.add(item.getProp_value());
                samlssoServiceProviderDO.setAssertionConsumerUrls(requestedRecipientsList.toArray(new String[0]));
                break;
            case ENABLE_ATTRIBUTES_BY_DEFAULT:
                samlssoServiceProviderDO.setEnableAttributesByDefault(item.getProp_value().equals("true"));
                break;
            case NAME_ID_CLAIM_URI:
                samlssoServiceProviderDO.setNameIdClaimUri(item.getProp_value());
                break;
            case NAME_ID_FORMAT:
                samlssoServiceProviderDO.setNameIDFormat(item.getProp_value());
                if (samlssoServiceProviderDO.getNameIDFormat() == null) {
                    samlssoServiceProviderDO.setNameIDFormat(NameIdentifier.EMAIL);
                }
                samlssoServiceProviderDO.setNameIDFormat(samlssoServiceProviderDO.getNameIDFormat().replace(":", "/"));
                break;
            case IDP_INIT_SSO_ENABLED:
                samlssoServiceProviderDO.setIdPInitSSOEnabled(item.getProp_value().equals("true"));
                break;
            case IDP_INIT_SLO_ENABLED:
                samlssoServiceProviderDO.setIdPInitSLOEnabled(item.getProp_value().equals("true"));
                break;
            case IDP_INIT_SLO_RETURN_TO_URLS:
                String[] idpInitSLOReturnToURLsArray = samlssoServiceProviderDO.getIdpInitSLOReturnToURLs();
                ArrayList<String> idpInitSLOReturnToURLsList = new ArrayList<>(Arrays.asList(idpInitSLOReturnToURLsArray));
                idpInitSLOReturnToURLsList.add(item.getProp_value());
                samlssoServiceProviderDO.setAssertionConsumerUrls(idpInitSLOReturnToURLsList.toArray(new String[0]));
                break;
            case DO_ENABLE_ENCRYPTED_ASSERTION:
                samlssoServiceProviderDO.setDoEnableEncryptedAssertion(item.getProp_value().equals("true"));
                break;
            case DO_VALIDATE_SIGNATURE_IN_REQUESTS:
                samlssoServiceProviderDO.setDoValidateSignatureInRequests(item.getProp_value().equals("true"));
                break;
            case IDP_ENTITY_ID_ALIAS:
                samlssoServiceProviderDO.setIdpEntityIDAlias(item.getProp_value());
                break;
        }
        return samlssoServiceProviderDO;
    }


}
