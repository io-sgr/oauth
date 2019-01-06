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

package io.sgr.oauth.server.authserver.j2ee;

import static org.mockito.ArgumentMatchers.any;
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
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.dummy.DummyBackend;
import io.sgr.oauth.server.authserver.j2ee.dummy.DummyTokenServlet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RunWith(MockitoJUnitRunner.class)
public class TokenServletTest {

	private DummyTokenServlet servlet;

	@Mock
	private AuthorizationServer mockAuthServer;
	@Mock
	private DummyBackend mockBackend;
	@Mock
	private HttpServletRequest mockReq;
	@Mock
	private HttpServletResponse mockResp;
	@Mock
	private OAuthCredential mockCredential;
	@Mock
	private PrintWriter mockWriter;

	@Before
	public void init() {
		servlet = new DummyTokenServlet(mockAuthServer, mockBackend);
	}

	@Test
	public void testGenerateToken()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenReturn(mockCredential);
		when(mockResp.getWriter()).thenReturn(mockWriter);
		servlet.doPost(mockReq, mockResp);
		verify(mockWriter, times(1)).write(any(String.class));
	}

	@Test
	public void testServerErrorException()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenThrow(new ServerErrorException(""));
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onServerError(any(OAuthError.class));
	}

	@Test
	public void testInvalidClientException()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenThrow(new InvalidClientException(""));
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onInvalidClient(any(OAuthError.class));
	}

	@Test
	public void testUnsupportedGrantTypeException()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenThrow(new UnsupportedGrantTypeException(""));
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadTokenRequest(any(OAuthError.class));
	}

	@Test
	public void testInvalidScopeException()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenThrow(new InvalidScopeException(""));
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadTokenRequest(any(OAuthError.class));
	}

	@Test
	public void testInvalidGrantException()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenThrow(new InvalidGrantException(""));
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadTokenRequest(any(OAuthError.class));
	}

	@Test
	public void testInvalidRequestException()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenThrow(new InvalidRequestException(""));
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onBadTokenRequest(any(OAuthError.class));
	}

	@Test
	public void testGeneratedNull()
			throws ServletException, IOException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException, InvalidRequestException, InvalidClientException {
		when(mockAuthServer.generateToken(any(), any())).thenReturn(null);
		servlet.doPost(mockReq, mockResp);
		verify(mockBackend, times(1)).onServerError(any(OAuthError.class));
	}

}
