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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;

public class OAuthServerUtilTest {

	@Test
	public void testGetBaseEndpointFromRedirectUri() throws UnsupportedEncodingException {
		final String uri = "https://localhost:443/callback?extra_params=aaa&another=";
		final String encoded = URLEncoder.encode(uri, "UTF-8");
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
		final String baseEndpoint = OAuthServerUtil.toBaseEndpoint(encoded);
		assertEquals("https://localhost:443/callback", baseEndpoint);
	}

	@Test
	public void testValidateRedirectUri() {
		try {
			OAuthServerUtil.isRedirectUriRegistered(null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			OAuthServerUtil.isRedirectUriRegistered("aaa", null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			OAuthServerUtil.isRedirectUriRegistered(null, Collections.singletonList("http://localhost/callback"));
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
	}

}
