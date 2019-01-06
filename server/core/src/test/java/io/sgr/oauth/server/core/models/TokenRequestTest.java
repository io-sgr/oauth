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
import static org.junit.Assert.fail;

import io.sgr.oauth.core.v20.GrantType;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.UUID;

public class TokenRequestTest {

	@Test
	public void testGetters() throws UnsupportedEncodingException {
		final GrantType grantType = GrantType.AUTHORIZATION_CODE;
		final String clientId = UUID.randomUUID().toString();
		final String clientSecret = UUID.randomUUID().toString();
		final String redirectUri = "http://localhost/callback?test=123";
		final String encodedRedirectUri = URLEncoder.encode(redirectUri, "UTF-8");
		TokenRequest req;
		req = new TokenRequest(grantType, clientId, clientSecret, encodedRedirectUri, null, null, null, null, null);
		assertEquals(grantType, req.getGrantType());
		assertEquals(clientId, req.getClientId());
		assertEquals(clientSecret, req.getClientSecret());
		assertEquals(redirectUri, req.getRedirectUri());
		assertFalse(req.getCode().isPresent());
		assertFalse(req.getRefreshToken().isPresent());
		assertFalse(req.getUsername().isPresent());
		assertFalse(req.getPassword().isPresent());
		assertFalse(req.getScopes().isPresent());
	}

	@Test
	public void testConstructWithInvalidArguments() {
		try {
			new TokenRequest(null, null, null, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			new TokenRequest(GrantType.AUTHORIZATION_CODE, null, null, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			new TokenRequest(GrantType.AUTHORIZATION_CODE, UUID.randomUUID().toString(), null, null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			new TokenRequest(GrantType.AUTHORIZATION_CODE, UUID.randomUUID().toString(), UUID.randomUUID().toString(), null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
	}

}
