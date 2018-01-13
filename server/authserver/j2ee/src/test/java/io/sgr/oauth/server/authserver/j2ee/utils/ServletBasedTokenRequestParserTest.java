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

package io.sgr.oauth.server.authserver.j2ee.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.server.core.models.TokenRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

@RunWith(MockitoJUnitRunner.class)
public class ServletBasedTokenRequestParserTest {

	private static final ServletBasedTokenRequestParser PARSER = ServletBasedTokenRequestParser.instance();

	@Mock
	private HttpServletRequest mockReq;

	@Test
	public void testParse() throws InvalidRequestException, UnsupportedGrantTypeException {
		final String grantType = GrantType.ASSERTION.name();
		final String clientId = UUID.randomUUID().toString();
		final String clientSecret = UUID.randomUUID().toString();
		final String redirectUri = "http://localhost/callback";
		when(mockReq.getParameterValues(OAuth20.OAUTH_GRANT_TYPE)).thenReturn(new String[] { grantType });
		when(mockReq.getParameter(OAuth20.OAUTH_GRANT_TYPE)).thenReturn(grantType);
		when(mockReq.getParameterValues(OAuth20.OAUTH_CLIENT_ID)).thenReturn(new String[] { clientId });
		when(mockReq.getParameter(OAuth20.OAUTH_CLIENT_ID)).thenReturn(clientId);
		when(mockReq.getParameterValues(OAuth20.OAUTH_CLIENT_SECRET)).thenReturn(new String[] { clientSecret });
		when(mockReq.getParameter(OAuth20.OAUTH_CLIENT_SECRET)).thenReturn(clientSecret);
		when(mockReq.getParameterValues(OAuth20.OAUTH_REDIRECT_URI)).thenReturn(new String[] { redirectUri });
		when(mockReq.getParameter(OAuth20.OAUTH_REDIRECT_URI)).thenReturn(redirectUri);
		final TokenRequest req = PARSER.parse(mockReq);
		assertNotNull(req);
		assertEquals(GrantType.ASSERTION, req.getGrantType());
		assertEquals(clientId, req.getClientId());
		assertEquals(clientSecret, req.getClientSecret());
		assertEquals(redirectUri, req.getRedirectUri());
	}

	@Test(expected = UnsupportedGrantTypeException.class)
	public void testParseWithUnsupportedGrantType() throws InvalidRequestException, UnsupportedGrantTypeException {
		final String respType = "abc";
		when(mockReq.getParameterValues(OAuth20.OAUTH_GRANT_TYPE)).thenReturn(new String[] { respType });
		when(mockReq.getParameter(OAuth20.OAUTH_GRANT_TYPE)).thenReturn(respType);
		PARSER.parse(mockReq);
	}

	@Test(expected = InvalidRequestException.class)
	public void testParseFromBlank() throws InvalidRequestException, UnsupportedGrantTypeException {
		PARSER.parse(mockReq);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseFromNull() throws InvalidRequestException, UnsupportedGrantTypeException {
		PARSER.parse(null);
	}

}
