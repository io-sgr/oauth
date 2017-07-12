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
package io.sgr.oauth.core;

import io.sgr.oauth.core.utils.JsonUtil;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * @author SgrAlpha
 *
 */
public class OAuthCredentialTest {

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
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential("abcdefghijklmn", "");
		assertEquals("abcdefghijklmn", credential.getAccessToken());
		assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());

		credential = new OAuthCredential("abcdefghijklmn", "test_type");
		assertEquals("abcdefghijklmn", credential.getAccessToken());
		assertEquals("test_type", credential.getTokenType());
		assertNull(credential.getAccessTokenExpiration());
		assertNull(credential.getAccessTokenExpiresIn());
		assertNull(credential.getRefreshToken());
		assertNull(credential.getExtraParams());
	}
	
	@Test
	public void testConstructOAuthCredentialFromJson() {
		OAuthCredential credential;
		
		try {
			credential = JsonUtil.getObjectMapper().readValue("{}", OAuthCredential.class);
			Assert.assertNotNull(credential);
			assertNull(credential.getAccessToken());
			assertNull(credential.getTokenType());
			assertNull(credential.getAccessTokenExpiresIn());
			assertNull(credential.getAccessTokenExpiration());
			assertNull(credential.getRefreshToken());
			assertNull(credential.getExtraParams());
			
			credential = JsonUtil.getObjectMapper().readValue("{\"access_token\":\"aaa\", \"token_type\":\"Bearer\", \"expires_in\":-1, \"refresh_token\":\"ccc\", \"id_token\":\"ddd\" }", OAuthCredential.class);
			System.out.println(credential);
			Assert.assertNotNull(credential);
			Assert.assertEquals("aaa", credential.getAccessToken());
			Assert.assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
//			Assert.assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
			Assert.assertEquals("ccc", credential.getRefreshToken());
			Assert.assertNotNull(credential.getExtraParams());
			Assert.assertNotNull(credential.getExtraParams().get("id_token"));
			Assert.assertEquals("ddd", credential.getExtraParams().get("id_token"));
			
			credential = JsonUtil.getObjectMapper().readValue("{\"access_token\":\"aaa\", \"token_type\":\"Bearer\", \"expires_in\":-1, \"refresh_token\":\"ccc\", \"ddd\": 1024 }", OAuthCredential.class);
			System.out.println(credential);
			Assert.assertNotNull(credential);
			Assert.assertEquals("aaa", credential.getAccessToken());
			Assert.assertEquals(OAuthCredential.DEFAULT_TOKEN_TYPE, credential.getTokenType());
//			Assert.assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
			Assert.assertEquals("ccc", credential.getRefreshToken());
			Assert.assertNotNull(credential.getExtraParams());
			Assert.assertEquals(1, credential.getExtraParams().size());
			Assert.assertEquals(1024, credential.getExtraParams().get("ddd"));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.getMessage());
		}
		
	}

}
