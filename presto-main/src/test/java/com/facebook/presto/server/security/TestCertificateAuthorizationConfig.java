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

import com.facebook.airlift.configuration.testing.ConfigAssertions;
import org.testng.annotations.Test;

public class TestCertificateAuthorizationConfig
{
    @Test
    public void testDefaults()
    {
        //todo remove defaults
        String defaultMapString = "{ \"/v1/info/state\" : [\"CN=svc:presto.coordinator.https\", \"presto-team\", \"presto-admin\"], " +
                "\"/v1/task\" : [\"CN=svc:presto.coordinator.https\"], " +
                "\" /v1/memory\" : [\"CN=svc:presto.coordinator.https\"], " +
                "\"/v1/smcServiceInventory\" : [\"CN=svc:presto.coordinator.https\"], " +
                "\"/v1/announcement\" : [\"CN=svc:presto.coordinator.https\"] }";
        ConfigAssertions.assertRecordedDefaults(ConfigAssertions.recordDefaults(CertificateAuthorizationConfig.class)
                .setAllowedIdentitiesMap(defaultMapString));
    }

    @Test
    public void testExplicitPropertyMappings()
    {
    }
}
