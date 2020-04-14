/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.server.security;

import com.facebook.airlift.log.Logger;
import com.google.inject.Inject;

import javax.servlet.http.HttpServletRequest;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

public class CertificateIdentityAuthorizer
        implements Authorizer
{
    private static final String X509_ATTRIBUTE = "javax.servlet.request.X509Certificate";
    private static final Logger log = Logger.get(CertificateIdentityAuthorizer.class);
    private Map<String, Set<String>> allowedIdentitiesMap;

    @Inject
    public CertificateIdentityAuthorizer(CertificateAuthorizationConfig certificateAuthorizationConfig)
    {
        this.allowedIdentitiesMap = certificateAuthorizationConfig.getAllowedIdentitiesMap();
    }

    @Override
    public boolean authorize(HttpServletRequest request)
    {
        if (!shouldCheckAuthorization(request)) {
            log.info("authz: NOT validating Request URL. %s method: %s uri: %s", request.toString(), request.getMethod(), request.getRequestURI());
            return true;
        }

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(X509_ATTRIBUTE);

        if (certs == null || certs.length == 0) {
            // deny access
            log.info("authz: No Cert: authorization FAILED for request: %s", request.toString());
            return false;
        }

        log.info("authz: Certs length: %s", certs.length);
        for (X509Certificate cert : certs) {
            log.info("authz: cert details: %s", cert.getSubjectX500Principal().getName());
            Principal principal = cert.getSubjectX500Principal();
            for (String endpoint : allowedIdentitiesMap.keySet()) {
                if (request.getRequestURI().startsWith(endpoint)) {
                    if (allowedIdentitiesMap.get(endpoint).contains(principal.getName())) {
                        // success
                        log.info("authz: Successfully authorized %s request %s", principal.getName(), request.getRequestURI());
                        return true;
                    }
                    else {
                        log.info("authz: denied: 1");
                        return false;
                    }
                }
            }
        }

        log.info("authz: denied: 2");
        return false;
    }

    private boolean shouldCheckAuthorization(HttpServletRequest request)
    {
        for (String endpoint : allowedIdentitiesMap.keySet()) {
            if (request.getRequestURI().startsWith(endpoint)) {
                return true;
            }
        }
        return false;
    }
}
