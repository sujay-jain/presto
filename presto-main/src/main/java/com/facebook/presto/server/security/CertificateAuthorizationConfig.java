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
import com.facebook.airlift.log.Logger;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.validation.constraints.NotNull;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class CertificateAuthorizationConfig
{
    private static final Logger log = Logger.get(CertificateAuthorizationConfig.class);
    /*
    example config:
            config_props[
                "http.server.authorization.certificate.allowedIdentitiesByEndpoint"] =
                "{ "/v1/info/state" : ["CN=svc:presto.coordinator.https", "presto-team", "presto-admin"],
                "/v1/task\" : ["CN=svc:presto.coordinator.https"],
                "/v1/memory" : ["CN=svc:presto.coordinator.https"],
                "/v1/smcServiceInventory" : ["CN=svc:presto.coordinator.https"],
                "/v1/announcement" : ["CN=svc:presto.coordinator.https"] }"
     */

    // todo remove defaults
    private Map<String, Set<String>> allowedIdentitiesMap = createDefaultMap();

    @Config("http.server.authorization.certificate.allowedIdentitiesByEndpoint")
    public CertificateAuthorizationConfig setAllowedIdentitiesMap(String inputMapString)
    {
        try {
            allowedIdentitiesMap = new ObjectMapper().readValue(inputMapString, new TypeReference<Map<String, Set<String>>>() {});
            for (String key : allowedIdentitiesMap.keySet()) {
                log.info("authz: key %s values %s", key, String.join(", ", allowedIdentitiesMap.get(key)));
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return this;
    }

    @NotNull
    public Map<String, Set<String>> getAllowedIdentitiesMap()
    {
        return allowedIdentitiesMap;
    }

    //todo remove this -- only for testing
    private Map<String, Set<String>> createDefaultMap()
    {
        String jsonString =
                "{ \"/v1/info/state\" : [\"CN=svc:presto.coordinator.https\", \"presto-team\", \"presto-admin\"]," +
                        "\"/v1/task\" : [\"CN=svc:presto.coordinator.https\"], " +
                        "\" /v1/memory\" : [\"CN=svc:presto.coordinator.https\"], " +
                        "\"/v1/smcServiceInventory\" : [\"CN=svc:presto.coordinator.https\"], " +
                        "\"/v1/announcement\" : [\"CN=svc:presto.coordinator.https\"] }";

        Map<String, Set<String>> map = new HashMap<>();
        try {
            map = new ObjectMapper().readValue(jsonString, new TypeReference<Map<String, Set<String>>>() {});
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return map;
    }
}
