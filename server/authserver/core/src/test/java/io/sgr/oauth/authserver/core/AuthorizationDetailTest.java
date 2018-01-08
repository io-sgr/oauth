package io.sgr.oauth.authserver.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;
import org.junit.Test;

import java.time.Clock;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class AuthorizationDetailTest {

	private static final OAuthClientInfo TEST_CLIENT = new OAuthClientInfo(
			UUID.randomUUID().toString(), UUID.randomUUID().toString(),
			"name", null, null, null, "user_1", Clock.systemUTC().millis());

	@Test
	public void testGetters() {
		final List<ScopeDefinition> scopes = Collections.singletonList(new ScopeDefinition("basic", "Basic", "Basic Scope"));
		AuthorizationDetail authDetail;
		authDetail = new AuthorizationDetail(ResponseType.CODE, TEST_CLIENT, "user_1", "http://localhost/callback", scopes, null);
		assertEquals(ResponseType.CODE, authDetail.getResponseType());
		assertEquals(TEST_CLIENT, authDetail.getClient());
		assertEquals("user_1", authDetail.getCurrentUser());
		assertEquals("http://localhost/callback", authDetail.getRedirectUri());
		assertEquals(scopes.get(0), authDetail.getScopes().get(0));
		assertFalse(authDetail.getState().isPresent());

	}

	@Test
	public void testConstructWithInvalidArguments() {
		try {
			new AuthorizationDetail(null, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new AuthorizationDetail(ResponseType.CODE, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new AuthorizationDetail(ResponseType.CODE, TEST_CLIENT, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new AuthorizationDetail(ResponseType.CODE, TEST_CLIENT, "user_1", null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new AuthorizationDetail(ResponseType.CODE, TEST_CLIENT, "user_1", "http://localhost/callback", null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			new AuthorizationDetail(ResponseType.CODE, TEST_CLIENT, "user_1", "http://localhost/callback", Collections.emptyList(), null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
	}

}
