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

package io.sgr.oauth.server.core.models;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import io.sgr.oauth.core.v20.ResponseType;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class AuthorizationRequestTest {

    @Test
    public void testGetters() throws UnsupportedEncodingException {
        final ResponseType responseType = ResponseType.CODE;
        final String clientId = UUID.randomUUID().toString();
        final String redirectUri = "http://localhost/callback?test=123";
        final String encodedRedirectUri = URLEncoder.encode(redirectUri, "UTF-8");
        final List<String> scopes = Collections.singletonList("basic");
        AuthorizationRequest req;
        req = new AuthorizationRequest(responseType, clientId, encodedRedirectUri, scopes, null);
        assertEquals(responseType, req.getResponseType());
        assertEquals(clientId, req.getClientId());
        assertEquals(redirectUri, req.getRedirectUri());
        assertNotNull(req.getScopes());
        assertFalse(req.getScopes().isEmpty());
        assertEquals("basic", req.getScopes().get(0));
        assertFalse(req.getState().isPresent());
        final String state = UUID.randomUUID().toString();
        req = new AuthorizationRequest(responseType, clientId, encodedRedirectUri, scopes, state);
        assertEquals(state, req.getState().orElse(null));
    }

    @Test
    public void testConstructWithInvalidArguments() {
        try {
            new AuthorizationRequest(null, null, null, null, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            new AuthorizationRequest(ResponseType.CODE, null, null, null, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            new AuthorizationRequest(ResponseType.CODE, UUID.randomUUID().toString(), null, null, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            new AuthorizationRequest(ResponseType.CODE, UUID.randomUUID().toString(), "http://localhost/callback", null, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            new AuthorizationRequest(ResponseType.CODE, UUID.randomUUID().toString(), "http://localhost/callback", Collections.emptyList(), null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

}
