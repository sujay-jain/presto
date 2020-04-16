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
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableSet;

import javax.validation.constraints.NotNull;

import java.util.Set;

import static java.util.Objects.requireNonNull;

public class AuthorizationConfig
{
    private boolean enabled = true;
    // todo remove defaults
    private Set<String> allowedIdentities = ImmutableSet.of("CN=svc:presto.coordinator.https");
    private Set<String> authorizedEndpoints = ImmutableSet.of("/v1/info/state", "/v1/task", "/v1/smcServiceInventory", "/v1/memory", "/v1/announcement");

    public boolean isEnabled()
    {
        return enabled;
    }

    @Config("endpoint-authorization.enabled")
    public AuthorizationConfig setEnabled(boolean enabled)
    {
        this.enabled = enabled;
        return this;
    }

    @Config("endpoint-authorization.allowed-identities")
    public AuthorizationConfig setAllowedIdentities(String whitelist)
    {
        this.allowedIdentities = ImmutableSet.copyOf(Splitter.on(",").split(
                requireNonNull(whitelist, "allowedIdentities is null")));
        return this;
    }

    @NotNull
    public Set<String> getAllowedIdentities()
    {
        return allowedIdentities;
    }

    @Config("endpoint-authorization.authorized-endpoints")
    public AuthorizationConfig setAuthorizedEndpoints(String authorizedEndpoints)
    {
        this.allowedIdentities = ImmutableSet.copyOf(Splitter.on(",").split(
                requireNonNull(authorizedEndpoints, "allowedIdentities is null")));
        return this;
    }

    @NotNull
    public Set<String> getAuthorizedEndpoints()
    {
        return authorizedEndpoints;
    }
}
