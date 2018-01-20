/*
 * Copyright 2017-2018 SgrAlpha
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OAuthServerUtilTest {

	@Test
	public void testGetBaseEndpointFromRedirectUri() {
		final String uri = "https://localhost:443/callback?extra_params=aaa&another=";
		try {
			OAuthServerUtil.toBaseEndpoint(null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			OAuthServerUtil.toBaseEndpoint("");
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		final String baseEndpoint = OAuthServerUtil.toBaseEndpoint(uri);
		assertEquals("https://localhost:443/callback", baseEndpoint);
	}

	@Test
	public void testValidateRedirectUri() {
		try {
			OAuthServerUtil.isRedirectUriRegistered(null, Collections.emptyList());
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			OAuthServerUtil.isRedirectUriRegistered("\n", Collections.singletonList("http://localhost/callback"));
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("aaa", (String) null));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("aaa", (String[]) null));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback"));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", "http://somewhere/callback"));
		assertTrue(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", "http://localhost/callback"));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("aaa", (List<String>) null));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", Collections.emptyList()));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", Collections.singletonList("http://somewhere/callback")));
		assertTrue(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", Collections.singletonList("http://localhost/callback")));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("aaa", (Set<String>) null));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", Collections.emptySet()));
		assertFalse(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", new HashSet<>(Collections.singletonList("http://somewhere/callback"))));
		assertTrue(OAuthServerUtil.isRedirectUriRegistered("http://localhost/callback", new HashSet<>(Collections.singletonList("http://localhost/callback"))));
	}

	@Test
	public void testParseOAuthCredentialFromAuthHeader() {
		assertNull(OAuthServerUtil.parseAccessTokenFromAuthorization(null));
		assertNull(OAuthServerUtil.parseAccessTokenFromAuthorization("\n"));
		assertNull(OAuthServerUtil.parseAccessTokenFromAuthorization("abc"));
		assertNotNull(OAuthServerUtil.parseAccessTokenFromAuthorization("Bearer asadas"));
	}

}
