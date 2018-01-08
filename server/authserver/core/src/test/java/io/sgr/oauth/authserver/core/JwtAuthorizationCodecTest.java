package io.sgr.oauth.authserver.core;

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
