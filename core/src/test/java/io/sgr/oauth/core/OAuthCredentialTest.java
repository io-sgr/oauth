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

import org.junit.Assert;
import org.junit.Test;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.utils.JsonUtil;

/**
 * @author SgrAlpha
 *
 */
public class OAuthCredentialTest {
	
	@Test
	public void testOAuthCredential() {
		OAuthCredential credential = null;
		
		try {
			credential = JsonUtil.getObjectMapper().readValue("{}", OAuthCredential.class);
			Assert.assertNotNull(credential);
			Assert.assertNull(credential.getAccessToken());
			Assert.assertNull(credential.getTokenType());
			Assert.assertNull(credential.getAccessTokenExpiresIn());
			Assert.assertNull(credential.getAccessTokenExpiration());
			Assert.assertNull(credential.getRefreshToken());
			Assert.assertNull(credential.getExtraParams());
			
			credential = JsonUtil.getObjectMapper().readValue("{\"access_token\":\"aaa\", \"token_type\":\"Bearer\", \"expires_in\":-1, \"refresh_token\":\"ccc\", \"id_token\":\"ddd\" }", OAuthCredential.class);
			System.out.println(credential);
			Assert.assertNotNull(credential);
			Assert.assertEquals("aaa", credential.getAccessToken());
			Assert.assertEquals("Bearer", credential.getTokenType());
//			Assert.assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
			Assert.assertEquals("ccc", credential.getRefreshToken());
			Assert.assertNotNull(credential.getExtraParams());
			Assert.assertNotNull(credential.getExtraParams().get("id_token"));
			Assert.assertEquals("ddd", credential.getExtraParams().get("id_token"));
			
			credential = JsonUtil.getObjectMapper().readValue("{\"access_token\":\"aaa\", \"token_type\":\"Bearer\", \"expires_in\":-1, \"refresh_token\":\"ccc\", \"ddd\": 1024 }", OAuthCredential.class);
			System.out.println(credential);
			Assert.assertNotNull(credential);
			Assert.assertEquals("aaa", credential.getAccessToken());
			Assert.assertEquals("Bearer", credential.getTokenType());
//			Assert.assertTrue(OAuthCredential.DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC >= credential.getAccessTokenExpiresIn());
			Assert.assertEquals("ccc", credential.getRefreshToken());
			Assert.assertNotNull(credential.getExtraParams());
			Assert.assertEquals(1, credential.getExtraParams().size());
			Assert.assertEquals(1024, credential.getExtraParams().get("ddd"));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.getMessage());
		} finally {
			
		}
		
	}

}
