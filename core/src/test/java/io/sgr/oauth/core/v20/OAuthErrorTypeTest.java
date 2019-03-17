/*
 * Copyright 2017-2019 SgrAlpha
 *
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
 *
 */

package io.sgr.oauth.core.v20;

import static io.sgr.oauth.core.v20.OAuthErrorType.ACCESS_DENIED;
import static io.sgr.oauth.core.v20.OAuthErrorType.INVALID_CLIENT;
import static io.sgr.oauth.core.v20.OAuthErrorType.INVALID_GRANT;
import static io.sgr.oauth.core.v20.OAuthErrorType.INVALID_REQUEST;
import static io.sgr.oauth.core.v20.OAuthErrorType.INVALID_SCOPE;
import static io.sgr.oauth.core.v20.OAuthErrorType.SERVER_ERROR;
import static io.sgr.oauth.core.v20.OAuthErrorType.TEMPORARILY_UNAVAILABLE;
import static io.sgr.oauth.core.v20.OAuthErrorType.UNAUTHORIZED_CLIENT;
import static io.sgr.oauth.core.v20.OAuthErrorType.UNSUPPORTED_GRANT_TYPE;
import static io.sgr.oauth.core.v20.OAuthErrorType.UNSUPPORTED_RESPONSE_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.type.CollectionType;

import io.sgr.oauth.core.utils.JsonUtil;

import org.junit.Test;

import java.io.IOException;
import java.util.List;

public class OAuthErrorTypeTest {

    @Test
    public void testToJson() throws JsonProcessingException {
        final String json = JsonUtil.getObjectMapper().writeValueAsString(OAuthErrorType.values());
        System.out.println(json);
        assertEquals(
                "[\"invalid_request\",\"invalid_scope\",\"unauthorized_client\",\"invalid_client\",\"unsupported_response_type\",\"invalid_grant\","
                        + "\"unsupported_grant_type\",\"access_denied\",\"server_error\",\"temporarily_unavailable\"]",
                json);
    }

    @Test
    public void testFromJson() throws IOException {
        final String json =
                "[\"invalid_request\",\"invalid_scope\",\"unauthorized_client\",\"invalid_client\",\"unsupported_response_type\",\"invalid_grant\","
                        + "\"unsupported_grant_type\",\"access_denied\",\"server_error\",\"temporarily_unavailable\"]";
        final CollectionType type = JsonUtil.getObjectMapper().getTypeFactory().constructCollectionType(List.class, OAuthErrorType.class);
        final List<OAuthErrorType> types = JsonUtil.getObjectMapper().readValue(json, type);
        assertNotNull(types);
        assertEquals(10, types.size());
        assertEquals(INVALID_REQUEST, types.get(0));
        assertEquals(INVALID_SCOPE, types.get(1));
        assertEquals(UNAUTHORIZED_CLIENT, types.get(2));
        assertEquals(INVALID_CLIENT, types.get(3));
        assertEquals(UNSUPPORTED_RESPONSE_TYPE, types.get(4));
        assertEquals(INVALID_GRANT, types.get(5));
        assertEquals(UNSUPPORTED_GRANT_TYPE, types.get(6));
        assertEquals(ACCESS_DENIED, types.get(7));
        assertEquals(SERVER_ERROR, types.get(8));
        assertEquals(TEMPORARILY_UNAVAILABLE, types.get(9));
    }

}
