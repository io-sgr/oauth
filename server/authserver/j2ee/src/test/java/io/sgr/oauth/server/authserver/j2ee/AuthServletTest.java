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

package io.sgr.oauth.server.authserver.j2ee;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.UnsupportedResponseTypeException;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.authserver.core.AuthorizationDetail;
import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.dummy.DummyAuthServlet;
import io.sgr.oauth.server.authserver.j2ee.dummy.DummyBackend;
import io.sgr.oauth.server.authserver.j2ee.utils.OAuthV2WebConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@RunWith(MockitoJUnitRunner.class)
public class AuthServletTest {

	private DummyAuthServlet servlet;

	@Mock
	private AuthorizationServer mockAuthServer;
	@Mock
	private DummyBackend mockBackend;
	@Mock
	private HttpServletRequest mockReq;
	@Mock
	private HttpServletResponse mockResp;
	@Mock
	private AuthorizationDetail mockAuthDetail;
	@Mock
	private HttpSession mockSession;

	@Before
	public void init() {
		servlet = new DummyAuthServlet(mockAuthServer, mockBackend);
	}

	@Test
	public void testAuthRequestWhenUserAlreadyAuthorized()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthDetail.isAlreadyAuthorized()).thenReturn(true);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenReturn(mockAuthDetail);
		servlet.doGet(mockReq, mockResp);
		verify(mockSession, never()).setAttribute(eq(OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_DETAIL), any(AuthorizationDetail.class));
		verify(mockSession, never()).setAttribute(eq(OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN), anyString());
		verify(mockBackend, never()).displayUserAuthorizePage(any(AuthorizationDetail.class));
	}

	@Test
	public void testAuthRequest()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthDetail.isAlreadyAuthorized()).thenReturn(false);
		when(mockReq.getSession(anyBoolean())).thenReturn(mockSession);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenReturn(mockAuthDetail);
		servlet.doGet(mockReq, mockResp);
		verify(mockSession, times(1)).setAttribute(eq(OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_DETAIL), any(AuthorizationDetail.class));
		verify(mockSession, times(1)).setAttribute(eq(OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN), anyString());
		verify(mockBackend, times(1)).displayUserAuthorizePage(any(AuthorizationDetail.class));
	}

	@Test
	public void testServerErrorException()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenReturn(null);
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).onServerError(any(OAuthError.class));
	}

	@Test
	public void testUnsupportedResponseTypeException()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenThrow(new UnsupportedResponseTypeException(""));
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadOAuthRequest(any(OAuthError.class));
	}

	@Test
	public void testInvalidScopeException()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenThrow(new InvalidScopeException(""));
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadOAuthRequest(any(OAuthError.class));
	}

	@Test
	public void testInvalidRequestException()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenThrow(new InvalidRequestException(""));
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadOAuthRequest(any(OAuthError.class));
	}

	@Test
	public void testInvalidClientException()
			throws ServletException, IOException, InvalidClientException, UnsupportedResponseTypeException, InvalidRequestException, InvalidScopeException {
		final String currentUser = "user_1";
		when(mockBackend.getCurrentUserId()).thenReturn(currentUser);
		when(mockAuthServer.preAuthorization(any(HttpServletRequest.class), any(), eq(currentUser), any())).thenThrow(new InvalidClientException(""));
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).onInvalidClient(any(OAuthError.class));
	}

	@Test
	public void testUserNotSignedIn()
			throws ServletException, IOException {
		when(mockBackend.getCurrentUserId()).thenReturn(null);
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).getCurrentUserId();
		verify(mockBackend, times(1)).onUserNotSignedIn();
	}

}
