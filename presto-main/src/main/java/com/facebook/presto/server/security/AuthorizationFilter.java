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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

public class AuthorizationFilter
        implements Filter
{
    private static final Logger log = Logger.get(AuthorizationFilter.class);

    private boolean authorizationEnabled;
    private List<Authorizer> authorizers;

    @Inject
    public AuthorizationFilter(SecurityConfig securityConfig, List<Authorizer> authorizers)
    {
        this.authorizationEnabled = securityConfig.isAuthorizationEnabled();
        this.authorizers = authorizers;
    }

    @Override
    public void init(FilterConfig filterConfig)
            throws ServletException
    {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain nextFilter)
            throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        log.info("Inside AuthZ Filter URI %s Path Info %s Request %s", request.getRequestURI(), request.getPathInfo(), request.toString());

        if (!authorizationEnabled || !request.isSecure()) {
            log.info("No AuthZ here.. %s", request.toString());
            nextFilter.doFilter(request, response);
            return;
        }

        log.info(" Applying AuthZ to request %s", request.toString());

        for (Authorizer authorizer : authorizers) {
            if (authorizer.authorize(request)) {
                nextFilter.doFilter(request, response);
                return;
            }
        }

        //deny access
        log.info("authorization FAILED for request: %s method: %s uri: %s", request.toString(), request.getMethod(), request.getRequestURI());
        response.sendError(SC_UNAUTHORIZED, "Not Authorized to access this resource");
    }

    @Override
    public void destroy()
    {
    }
}
