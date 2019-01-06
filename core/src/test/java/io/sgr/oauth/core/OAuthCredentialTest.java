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
package io.sgr.oauth.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import io.sgr.oauth.core.utils.JsonUtil;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * @author SgrAlpha
 *
 */
public class OAuthCredentialTest {

	@Test
	public void testSetExpiresInSec() {
		OAuthCredential credential;
		credential = new OAuthCredential(null, null);
		credential.setAccessTokenExpiresIn(null);
		assertNull(credential.getAccessTokenExpiration());
		credential.setAccessTokenExpiresIn(-1);
		assertNull(credential.getAccessTokenExpiration());
		credential.setAccessTokenExpiresIn((int) OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC);
		assertNull(credential.getAccessTokenExpiration());

		credential = new OAuthCredential("abcdefg", null);
		credential.setAccessTokenExpiresIn(null);
		assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
		credential.setAccessTokenExpiresIn(-1);
		assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
		credential.setAccessTokenExpiresIn((int) OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC);
		assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
	}

	@Test
	public void testOAuthCredential() {
		OAuthCredential credential;
		credential = new OAuthCredential(null, null);
		assertNull(credential.getAccessToken());
		assertNull(credential.getTokenType());
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential(null, "");
		assertNull(credential.getAccessToken());
		assertNull(credential.getTokenType());
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential("", null);
		assertNull(credential.getAccessToken());
		assertNull(credential.getTokenType());
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential(null, "test_type");
		assertNull(credential.getAccessToken());
		assertNull(credential.getTokenType());
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential("abcdefghijklmn", null);
		assertEquals("abcdefghijklmn", credential.getAccessToken());
		assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
		assertTrue(credential.getAccessTokenExpiration() > System.currentTimeMillis());
		assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential("abcdefghijklmn", "");
		assertEquals("abcdefghijklmn", credential.getAccessToken());
		assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
		assertTrue(credential.getAccessTokenExpiration() > System.currentTimeMillis());
		assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential("abcdefghijklmn", "test_type");
		final Map<String, Object> extraParams = new HashMap<>();
		extraParams.put("aaa", "value_aaa");
		extraParams.put("bbb", null);
		extraParams.put("ccc", true);
		credential.setExtraParams(extraParams);
		credential.addExtraParams("ddd", 1024);
		assertEquals("abcdefghijklmn", credential.getAccessToken());
		assertEquals("test_type", credential.getTokenType());
		assertTrue(credential.getAccessTokenExpiration() > System.currentTimeMillis());
		assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNotNull(credential.getExtraParams());
		assertTrue(credential.getExtraParams().containsKey("aaa"));
		assertEquals("value_aaa", credential.getExtraParams().get("aaa"));
		assertTrue(credential.getExtraParams().containsKey("bbb"));
		assertNull(credential.getExtraParams().get("bbb"));
		assertTrue(credential.getExtraParams().containsKey("ccc"));
		assertEquals(true, credential.getExtraParams().get("ccc"));
		assertTrue(credential.getExtraParams().containsKey("ddd"));
		assertEquals(1024, credential.getExtraParams().get("ddd"));
	}
	
	@Test
	public void testConstructOAuthCredentialFromJson() {
		OAuthCredential credential;
		
		try {
			credential = JsonUtil.getObjectMapper().readValue("{}", OAuthCredential.class);
			assertNotNull(credential);
			assertNull(credential.getAccessToken());
			assertNull(credential.getTokenType());
			assertNull(credential.getAccessTokenExpiresIn());
			assertNull(credential.getAccessTokenExpiration());
			assertNull(credential.getRefreshToken());
			assertNull(credential.getExtraParams());
			
			credential = JsonUtil.getObjectMapper().readValue("{\"access_token\":\"aaa\", \"token_type\":\"Bearer\", \"expires_in\":-1, \"refresh_token\":\"ccc\", \"id_token\":\"ddd\" }", OAuthCredential.class);
			System.out.println(credential);
			assertNotNull(credential);
			assertEquals("aaa", credential.getAccessToken());
			assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
			assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
			assertEquals("ccc", credential.getRefreshToken());
			assertNotNull(credential.getExtraParams());
			assertNotNull(credential.getExtraParams().get("id_token"));
			assertEquals("ddd", credential.getExtraParams().get("id_token"));
			
			credential = JsonUtil.getObjectMapper().readValue("{\"access_token\":\"aaa\", \"token_type\":\"Bearer\", \"expires_in\":-1, \"refresh_token\":\"ccc\", \"ddd\": 1024 }", OAuthCredential.class);
			System.out.println(credential);
			assertNotNull(credential);
			assertEquals("aaa", credential.getAccessToken());
			assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
			assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
			assertEquals("ccc", credential.getRefreshToken());
			assertNotNull(credential.getExtraParams());
			assertEquals(1, credential.getExtraParams().size());
			assertEquals(1024, credential.getExtraParams().get("ddd"));
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
		
	}

	@Test
	public void testOAuthCredentialToJson() {

	}

}
