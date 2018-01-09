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

package io.sgr.oauth.server.authserver.core;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import io.jsonwebtoken.ExpiredJwtException;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;
import org.junit.Test;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class JwtAuthorizationCodecTest {

	private static final OAuthClientInfo TEST_CLIENT = new OAuthClientInfo(
			UUID.randomUUID().toString(), UUID.randomUUID().toString(),
			"name", null, null, null, "user_1", Clock.systemUTC().millis());
	private static final List<ScopeDefinition> TEST_SCOPES = Collections.singletonList(new ScopeDefinition("basic", "Basic", "Basic Scope"));
	private static final AuthorizationDetail TEST_AUTH_DETAIL = new AuthorizationDetail(
			ResponseType.CODE, TEST_CLIENT, "user_1",
			"http://localhost/callback", TEST_SCOPES, null);

	@Test(expected = ExpiredJwtException.class)
	public void testEncodeDecode() throws InterruptedException {
		final JwtAuthorizationCodec codec = new JwtAuthorizationCodec("test_issuer", "test_secret").setExpiresIn(3, ChronoUnit.SECONDS);
		final String encoded = codec.encode(TEST_AUTH_DETAIL);
		assertNotNull(encoded);
		final AuthorizationDetail decoded = codec.decode(encoded);
		assertNotNull(decoded);
		TimeUnit.SECONDS.sleep(5);
		codec.decode(encoded);
	}

	@Test
	public void testConstructWithInvalidArguments() {
		try {
			new JwtAuthorizationCodec(null , null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new JwtAuthorizationCodec("test_issuer" , null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new JwtAuthorizationCodec("test_issuer" , "test_secret").setExpiresIn(-1, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new JwtAuthorizationCodec("test_issuer" , "test_secret").setExpiresIn(1, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
	}

}
