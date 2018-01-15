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

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.dummy.DummyAuthServlet;
import io.sgr.oauth.server.authserver.j2ee.dummy.DummyBackend;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

	@Before
	public void init() {
		servlet = new DummyAuthServlet(mockAuthServer, mockBackend);
	}

	@Test
	public void testUserNotSignedIn() throws ServletException, IOException {
		when(mockBackend.getCurrentUserId()).thenReturn(null);
		servlet.doGet(mockReq, mockResp);
		verify(mockBackend, times(1)).getCurrentUserId();
		verify(mockBackend, times(1)).onUserNotSignedIn();
	}

}
