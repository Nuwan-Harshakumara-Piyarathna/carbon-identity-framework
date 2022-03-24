package org.wso2.carbon.identity.core.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;

/**
 * Cached DAO layer for SAMLSSO Service Providers. All the DAO access has to be happen through this layer to ensure
 * single point of caching.
 */
public class CacheBackedSAMLSSOServiceProviderDAO {

    private static final Log log = LogFactory.getLog(CacheBackedSAMLSSOServiceProviderDAO.class);

    private final SAMLSSOServiceProviderDAO samlssoServiceProviderDAO;
    private final int tenantId;

    public CacheBackedSAMLSSOServiceProviderDAO(SAMLSSOServiceProviderDAO samlssoServiceProviderDAO,
                                                Registry registry) {
        this.samlssoServiceProviderDAO = samlssoServiceProviderDAO;
        if (registry instanceof UserRegistry) {
            UserRegistry userRegistry = (UserRegistry) registry;
            this.tenantId = userRegistry.getTenantId();
        } else {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            this.tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        }
    }

    public CacheBackedSAMLSSOServiceProviderDAO(SAMLSSOServiceProviderDAO samlssoServiceProviderDAO, int tenantId) {
        this.samlssoServiceProviderDAO = samlssoServiceProviderDAO;
        this.tenantId = tenantId;
    }

    public SAMLSSOServiceProviderDO getServiceProvider(String issuer) {
        return null;
    }

    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO) {
        return false;
    }

    public SAMLSSOServiceProviderDO uploadServiceProvider(SAMLSSOServiceProviderDO samlssoServiceProviderDO) {
        return null;
    }

    public SAMLSSOServiceProviderDO[] getServiceProviders() {
        return null;
    }

    public boolean removeServiceProvider() {
        return false;
    }

    public SAMLSSOServiceProviderDO getServiceProvider() {
        return null;
    }


    private void addServiceProviderToCache(SAMLSSOServiceProviderDO samlssoServiceProviderDO, String issuer) {
    }

}
