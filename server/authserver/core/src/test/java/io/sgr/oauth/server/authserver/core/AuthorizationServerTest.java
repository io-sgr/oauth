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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.ServerErrorException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.exceptions.UnsupportedResponseTypeException;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.OAuthErrorType;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.AuthRequestParser;
import io.sgr.oauth.server.core.OAuthV2Service;
import io.sgr.oauth.server.core.TokenRequestParser;
import io.sgr.oauth.server.core.models.AuthorizationRequest;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;
import io.sgr.oauth.server.core.models.TokenRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@RunWith(MockitoJUnitRunner.class)
public class AuthorizationServerTest {

	private static final String REGISTERED_CLIENT_ID = UUID.randomUUID().toString();
	private static final String REGISTERED_CLIENT_SECRET = UUID.randomUUID().toString();
	private static final String REGISTERED_CALLBACK = "http://localhost/callback";
	private static final OAuthClientInfo client = new OAuthClientInfo(
			REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET,
			"Client name", "Client desc", null, null,
			"super_user",
			Clock.systemUTC().millis(),
			Collections.singletonList(REGISTERED_CALLBACK));
	private static final String REGISTERED_SCOPE_ID = "basic";
	private static final ScopeDefinition REGISTERED_SCOPE = new ScopeDefinition(REGISTERED_SCOPE_ID, "Basic scope", "Scope desc");

	@Mock
	private OAuthV2Service mockService;
	@Mock
	private AuthRequestParser<Object> mockAuthReqParser;
	@Mock
	private TokenRequestParser<Object> mockTokenReqParser;

	private AuthorizationServer authServer;

	@Before
	public void initMock() {
		when(mockService.getOAuthClientById(eq(REGISTERED_CLIENT_ID))).thenReturn(Optional.of(client));
		when(mockService.getOAuthClientByIdAndSecret(eq(REGISTERED_CLIENT_ID), eq(REGISTERED_CLIENT_SECRET))).thenReturn(Optional.of(client));
		when(mockService.getScopeById(eq(REGISTERED_SCOPE_ID), any())).thenReturn(Optional.of(REGISTERED_SCOPE));
		authServer = AuthorizationServer
				.with(mockService)
				.setIssuer("unit_test").setServerSecret("test_secret")
				.setAuthCodeExpiresAfter(3L, ChronoUnit.SECONDS)
				.build();
	}

	@Test
	public void testRefreshAccessToken()
			throws InvalidGrantException, UnsupportedGrantTypeException, InvalidClientException, ServerErrorException, InvalidRequestException,
			InvalidScopeException {
		final String refreshToken = UUID.randomUUID().toString();
		final TokenRequest tokenReq = new TokenRequest(GrantType.REFRESH_TOKEN, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				null, refreshToken, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		when(mockService.isValidRefreshToken(REGISTERED_CLIENT_ID, refreshToken)).thenReturn(true);
		final OAuthCredential credential = new OAuthCredential(UUID.randomUUID().toString());
		when(mockService.refreshAccessToken(eq(REGISTERED_CLIENT_ID), eq(refreshToken))).thenReturn(credential);
		final OAuthCredential generated = authServer.generateToken(new Object(), mockTokenReqParser);
		assertEquals(credential.getAccessToken(), generated.getAccessToken());

		when(mockService.refreshAccessToken(eq(REGISTERED_CLIENT_ID), eq(refreshToken))).thenReturn(null);
		try {
			authServer.generateToken(new Object(), mockTokenReqParser);
			fail();
		} catch (ServerErrorException e) {
			// Expected
		}
	}

	@Test(expected = InvalidGrantException.class)
	public void testInvalidRefreshToken()
			throws InvalidGrantException, UnsupportedGrantTypeException, InvalidClientException, ServerErrorException, InvalidRequestException,
			InvalidScopeException {
		final String refreshToken = UUID.randomUUID().toString();
		final TokenRequest tokenReq = new TokenRequest(GrantType.REFRESH_TOKEN, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				null, refreshToken, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		when(mockService.isValidRefreshToken(REGISTERED_CLIENT_ID, refreshToken)).thenReturn(false);
		authServer.generateToken(new Object(), mockTokenReqParser);
	}

	@Test
	public void testAcquireAccessTokenWithAuthCode()
			throws InvalidRequestException, UnsupportedResponseTypeException, InvalidScopeException, InvalidClientException, ServerErrorException,
			UnsupportedGrantTypeException, InvalidGrantException, InterruptedException {
		final List<String> scopes = Collections.singletonList(REGISTERED_SCOPE_ID);
		final String state = UUID.randomUUID().toString();
		final AuthorizationRequest authReq = new AuthorizationRequest(ResponseType.CODE, REGISTERED_CLIENT_ID, REGISTERED_CALLBACK, scopes, state);
		when(mockAuthReqParser.parse(any())).thenReturn(authReq);
		final String currentUser = "user_1";
		final AuthorizationDetail authDetail = authServer.preAuthorization(new Object(), mockAuthReqParser, currentUser, null);
		assertNotNull(authDetail);
		assertEquals(authReq.getResponseType(), authDetail.getResponseType());
		assertEquals(client, authDetail.getClient());
		assertEquals(currentUser, authDetail.getCurrentUser());
		assertNotNull(authDetail.getScopes());
		assertEquals(1, authDetail.getScopes().size());
		assertEquals(REGISTERED_SCOPE, authDetail.getScopes().get(0));
		assertEquals(REGISTERED_CALLBACK, authDetail.getRedirectUri());
		assertTrue(authDetail.getState().isPresent());
		assertEquals(state, authDetail.getState().get());

		String url;
		url = authServer.postAuthorization(false, authDetail);
		assertTrue(url.contains(OAuth20.OAUTH_ERROR));
		assertEquals(OAuthErrorType.ACCESS_DENIED.name().toLowerCase(), fetchParamValueInUrl(url, OAuth20.OAUTH_ERROR));
		assertTrue(url.contains(OAuth20.OAUTH_ERROR_DESCRIPTION));
		assertTrue(url.contains(OAuth20.OAUTH_STATE));
		assertEquals(state, fetchParamValueInUrl(url, OAuth20.OAUTH_STATE));

		url = authServer.postAuthorization(true, authDetail);
		assertTrue(url.contains(OAuth20.OAUTH_CODE));
		assertTrue(url.contains(OAuth20.OAUTH_STATE));
		assertEquals(state, fetchParamValueInUrl(url, OAuth20.OAUTH_STATE));
		final String authCode = fetchParamValueInUrl(url, OAuth20.OAUTH_CODE);
		assertNotNull(authCode);

		TokenRequest tokenReq;
		tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		final OAuthCredential credential = new OAuthCredential(UUID.randomUUID().toString());
		when(mockService.isAuthorizationCodeRevoked(eq(authCode))).thenReturn(false);
		when(mockService.generateAccessToken(eq(REGISTERED_CLIENT_ID), eq(currentUser), anyCollection())).thenReturn(credential);
		final OAuthCredential generated = authServer.generateToken(new Object(), mockTokenReqParser);
		verify(mockService, times(1)).revokeAuthorizationCode(eq(authCode));
		assertEquals(credential.getAccessToken(), generated.getAccessToken());

		tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK + "?key=value",
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		try {
			authServer.generateToken(new Object(), mockTokenReqParser);
			fail();
		} catch (InvalidGrantException e) {
			// Expected because redirect URI mismatch
		} finally {
			verify(mockService, times(2)).revokeAuthorizationCode(eq(authCode));
		}

		tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		when(mockService.isAuthorizationCodeRevoked(eq(authCode))).thenReturn(true);
		try {
			authServer.generateToken(new Object(), mockTokenReqParser);
			fail();
		} catch (InvalidGrantException e) {
			// Expected because auth code has been revoked
		} finally {
			verify(mockService, times(2)).revokeAuthorizationCode(eq(authCode));
		}

		TimeUnit.SECONDS.sleep(3);

		tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		when(mockService.isAuthorizationCodeRevoked(eq(authCode))).thenReturn(false);
		try {
			authServer.generateToken(new Object(), mockTokenReqParser);
			fail();
		} catch (InvalidGrantException e) {
			// Expected because auth code is expired
		} finally {
			verify(mockService, times(3)).revokeAuthorizationCode(eq(authCode));
		}
	}

	private static String fetchParamValueInUrl(final String url, final String paramKey) {
		String value = url.substring(url.indexOf(paramKey) + paramKey.length() + 1);
		return value.substring(0, value.contains("&") ? value.indexOf("&") : value.length());
	}

	@Test(expected = InvalidGrantException.class)
	public void testInvalidAuthCode()
			throws InvalidRequestException, InvalidScopeException, InvalidClientException, UnsupportedGrantTypeException, InvalidGrantException,
			ServerErrorException {
		final String authCode = UUID.randomUUID().toString();
		final TokenRequest tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		try {
			authServer.generateToken(new Object(), mockTokenReqParser);
		} finally {
			verify(mockService, times(1)).revokeAuthorizationCode(eq(authCode));
		}
	}

	@Test(expected = InvalidGrantException.class)
	public void testInvalidRedirectUriWhenGenerateToken()
			throws InvalidRequestException, InvalidScopeException, InvalidClientException, UnsupportedGrantTypeException, InvalidGrantException,
			ServerErrorException {
		final String authCode = UUID.randomUUID().toString();
		final TokenRequest tokenReq = new TokenRequest(GrantType.NONE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, "http://localhost/redirect",
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		authServer.generateToken(new Object(), mockTokenReqParser);
	}

	@Test(expected = InvalidClientException.class)
	public void testInvalidClientWhenGenerateToken()
			throws InvalidRequestException, InvalidScopeException, InvalidClientException, UnsupportedGrantTypeException, InvalidGrantException,
			ServerErrorException {
		final String authCode = UUID.randomUUID().toString();
		final TokenRequest tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, "some_other_client", "some_other_secret", REGISTERED_CALLBACK,
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		authServer.generateToken(new Object(), mockTokenReqParser);
	}

	@Test(expected = UnsupportedGrantTypeException.class)
	public void testUnsupportedGrantType()
			throws InvalidRequestException, InvalidScopeException, InvalidClientException, UnsupportedGrantTypeException, InvalidGrantException,
			ServerErrorException {
		final String authCode = UUID.randomUUID().toString();
		final TokenRequest tokenReq = new TokenRequest(GrantType.NONE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				authCode, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		authServer.generateToken(new Object(), mockTokenReqParser);
	}

	@Test(expected = InvalidRequestException.class)
	public void testMissingAuthCode()
			throws InvalidRequestException, InvalidScopeException, InvalidClientException, UnsupportedGrantTypeException, InvalidGrantException,
			ServerErrorException {
		final TokenRequest tokenReq = new TokenRequest(GrantType.AUTHORIZATION_CODE, REGISTERED_CLIENT_ID, REGISTERED_CLIENT_SECRET, REGISTERED_CALLBACK,
				null, null, null, null, null);
		when(mockTokenReqParser.parse(any())).thenReturn(tokenReq);
		authServer.generateToken(new Object(), mockTokenReqParser);
	}

	@Test(expected = InvalidScopeException.class)
	public void testInvalidScope()
			throws InvalidRequestException, UnsupportedResponseTypeException, InvalidScopeException, InvalidClientException {
		final List<String> scopes = Arrays.asList(null, "", "bad_scope");
		final String state = UUID.randomUUID().toString();
		final AuthorizationRequest authReq = new AuthorizationRequest(ResponseType.CODE, REGISTERED_CLIENT_ID, REGISTERED_CALLBACK, scopes, state);
		when(mockAuthReqParser.parse(any())).thenReturn(authReq);
		authServer.preAuthorization(new Object(), mockAuthReqParser, "user_1", null);
	}

	@Test(expected = InvalidRequestException.class)
	public void testInvalidRedirectUri()
			throws InvalidRequestException, UnsupportedResponseTypeException, InvalidScopeException, InvalidClientException {
		final List<String> scopes = Collections.singletonList(REGISTERED_SCOPE_ID);
		final String state = UUID.randomUUID().toString();
		final AuthorizationRequest authReq = new AuthorizationRequest(ResponseType.CODE, REGISTERED_CLIENT_ID, "http://localhost/redirect", scopes, state);
		when(mockAuthReqParser.parse(any())).thenReturn(authReq);
		authServer.preAuthorization(new Object(), mockAuthReqParser, "user_1", null);
	}

	@Test(expected = InvalidClientException.class)
	public void testInvalidClient()
			throws InvalidRequestException, UnsupportedResponseTypeException, InvalidScopeException, InvalidClientException {
		final List<String> scopes = Collections.singletonList(REGISTERED_SCOPE_ID);
		final String state = UUID.randomUUID().toString();
		final AuthorizationRequest authReq = new AuthorizationRequest(ResponseType.CODE, "some_other_client", REGISTERED_CALLBACK, scopes, state);
		when(mockAuthReqParser.parse(any())).thenReturn(authReq);
		authServer.preAuthorization(new Object(), mockAuthReqParser, "user_1", null);
	}

	@Test(expected = UnsupportedResponseTypeException.class)
	public void testUnsupportedResponseType()
			throws InvalidRequestException, UnsupportedResponseTypeException, InvalidScopeException, InvalidClientException {
		final List<String> scopes = Collections.singletonList(REGISTERED_SCOPE_ID);
		final String state = UUID.randomUUID().toString();
		final AuthorizationRequest authReq = new AuthorizationRequest(ResponseType.CODE_AND_TOKEN, REGISTERED_CLIENT_ID, REGISTERED_CALLBACK, scopes, state);
		when(mockAuthReqParser.parse(any())).thenReturn(authReq);
		authServer.preAuthorization(new Object(), mockAuthReqParser, "user_1", null);
	}

	@Test
	public void testBuilder() {
		try {
			AuthorizationServer.with(null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			AuthorizationServer.with(mockService).setIssuer(null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		try {
			AuthorizationServer.with(mockService).setIssuer("unit_test").setServerSecret(null);
			fail();
		} catch (IllegalArgumentException e) {
			// Expected
		}
		final AuthorizationServer.Builder builder = AuthorizationServer
				.with(mockService)
				.setIssuer("unit_test").setServerSecret("test_secret")
				.setAuthCodeExpiresAfter(10L, ChronoUnit.SECONDS);
		assertNotNull(builder.getOAuthV2Service());
		assertEquals("unit_test", builder.getIssuer());
		assertEquals("test_secret", builder.getServerSecret());
		assertNotNull(builder.getAuthCodeExpiresTimeAmount());
		assertEquals(10L, builder.getAuthCodeExpiresTimeAmount().longValue());
		assertEquals(ChronoUnit.SECONDS, builder.getAuthCodeExpiresTimeUnit());
		builder.setAuthCodeExpiresAfter(null, null);
		assertNull(builder.getAuthCodeExpiresTimeAmount());
		assertNull(builder.getAuthCodeExpiresTimeUnit());
	}

}
