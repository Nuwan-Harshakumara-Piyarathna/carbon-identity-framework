package org.wso2.carbon.identity.core.cache;

import org.wso2.carbon.utils.CarbonUtils;

/**
 * SAMLSSOServiceProviderCache is used to cache saml service provider information.
 */
public class SAMLSSOServiceProviderCache extends BaseCache<CacheKey, CacheEntry>{

    private static final String SAMLSSO_SERVICE_PROVIDER_CACHE_NAME = "SAMLSSOServiceProviderCache";

    private static volatile SAMLSSOServiceProviderCache instance;

    private SAMLSSOServiceProviderCache() {
        super(SAMLSSO_SERVICE_PROVIDER_CACHE_NAME);
    }

    /**
     * Returns SAMLSSOServiceProviderCache instance
     *
     * @return instance of SAMLSSOServiceProviderCache
     */
    public static SAMLSSOServiceProviderCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (SAMLSSOServiceProviderCache.class) {
                if (instance == null) {
                    instance = new SAMLSSOServiceProviderCache();
                }
            }
        }
        return instance;
    }
}
