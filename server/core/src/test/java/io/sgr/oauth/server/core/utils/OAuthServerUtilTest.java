/*
 * Copyright 2017 SgrAlpha
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

package io.sgr.oauth.server.core.utils;

import static io.sgr.oauth.server.core.utils.OAuthServerUtil.isRedirectUriRegistered;
import static io.sgr.oauth.server.core.utils.OAuthServerUtil.parseAccessTokenFromAuthorization;
import static io.sgr.oauth.server.core.utils.OAuthServerUtil.toBaseEndpoint;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class OAuthServerUtilTest {

	@Test
	public void testGetBaseEndpointFromRedirectUri() {
		final String uri = "https://localhost:443/callback?extra_params=aaa&another=";
		try {
			toBaseEndpoint(null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			toBaseEndpoint("");
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		final String baseEndpoint = toBaseEndpoint(uri);
		assertEquals("https://localhost:443/callback", baseEndpoint);
	}

	@Test
	public void testValidateRedirectUri() {
		try {
			isRedirectUriRegistered(null, Collections.<String>emptyList());
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			isRedirectUriRegistered("\n", Collections.singletonList("http://localhost/callback"));
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		assertFalse(isRedirectUriRegistered("aaa", (String) null));
		assertFalse(isRedirectUriRegistered("aaa", (String[]) null));
		assertFalse(isRedirectUriRegistered("aaa", (List<String>) null));
		assertFalse(isRedirectUriRegistered("aaa", (Set<String>) null));
		assertTrue(isRedirectUriRegistered("http://localhost/callback", Collections.singletonList("http://localhost/callback")));
	}

	@Test
	public void testParseOAuthCredentialFromAuthHeader() {
		assertNull(parseAccessTokenFromAuthorization(null));
		assertNull(parseAccessTokenFromAuthorization("\n"));
		assertNull(parseAccessTokenFromAuthorization("abc"));
		assertNotNull(parseAccessTokenFromAuthorization("Bearer asadas"));
	}

}
