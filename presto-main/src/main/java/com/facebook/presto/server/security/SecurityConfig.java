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

import com.facebook.airlift.configuration.Config;
import com.facebook.airlift.configuration.ConfigDescription;
import com.facebook.airlift.configuration.DefunctConfig;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;

import javax.validation.constraints.NotNull;

import java.util.List;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.Streams.stream;

@DefunctConfig("http.server.authentication.enabled")
public class SecurityConfig
{
    private static final Splitter SPLITTER = Splitter.on(',').trimResults().omitEmptyStrings();

    private List<AuthenticationType> authenticationTypes = ImmutableList.of();
    private List<AuthorizationType> authorizationTypes = ImmutableList.of();

    //todo default false
    private boolean authorizationEnabled = true;

    public enum AuthenticationType
    {
        CERTIFICATE,
        KERBEROS,
        PASSWORD,
        JWT
    }

    public enum AuthorizationType
    {
        CERTIFICATE_IDENTITY
    }

    @NotNull
    public List<AuthenticationType> getAuthenticationTypes()
    {
        return authenticationTypes;
    }

    public SecurityConfig setAuthenticationTypes(List<AuthenticationType> authenticationTypes)
    {
        this.authenticationTypes = ImmutableList.copyOf(authenticationTypes);
        return this;
    }

    @Config("http-server.authentication.type")
    @ConfigDescription("Authentication types (supported types: CERTIFICATE, KERBEROS, PASSWORD, JWT)")
    public SecurityConfig setAuthenticationTypes(String types)
    {
        if (types == null) {
            authenticationTypes = null;
            return this;
        }

        authenticationTypes = stream(SPLITTER.split(types))
                .map(AuthenticationType::valueOf)
                .collect(toImmutableList());
        return this;
    }

    public boolean isAuthorizationEnabled()
    {
        return authorizationEnabled;
    }

    @Config("http-server.authorization.enabled")
    public SecurityConfig setAuthorizationEnabled(boolean authorizationEnabled)
    {
        this.authorizationEnabled = authorizationEnabled;
        return this;
    }

    @NotNull
    public List<AuthorizationType> getAuthorizationTypes()
    {
        return authorizationTypes;
    }

    public SecurityConfig setAuthorizationTypes(List<AuthorizationType> authorizationTypes)
    {
        this.authorizationTypes = ImmutableList.copyOf(authorizationTypes);
        return this;
    }

    @Config("http-server.authorization.type")
    @ConfigDescription("Authorization types (supported types: CERTIFICATE_IDENTITY)")
    public SecurityConfig setAuthorizationTypes(String types)
    {
        if (types == null) {
            authorizationTypes = null;
            return this;
        }

        authorizationTypes = stream(SPLITTER.split(types))
                .map(AuthorizationType::valueOf)
                .collect(toImmutableList());
        return this;
    }
}
