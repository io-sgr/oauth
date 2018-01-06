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

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;
import static io.sgr.oauth.core.v20.GrantType.AUTHORIZATION_CODE;

import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.server.core.TokenRequestParser;
import io.sgr.oauth.server.core.models.TokenRequest;

import java.text.MessageFormat;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

public class ServletBasedTokenRequestParser implements TokenRequestParser<HttpServletRequest> {

	private static final ServletBasedTokenRequestParser INSTANCE = new ServletBasedTokenRequestParser();

	private ServletBasedTokenRequestParser() {

	}

	public static ServletBasedTokenRequestParser instance() {
		return INSTANCE;
	}

	@Override public TokenRequest parse(final HttpServletRequest req)
			throws InvalidRequestException, UnsupportedGrantTypeException {
		notNull(req, "Missing HttpServletRequest");
		final String clientId = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_CLIENT_ID);
		final String clientSecret = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_CLIENT_SECRET);
		final String redirectUri = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_REDIRECT_URI);
		final String grantTypeS = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_GRANT_TYPE);
		final GrantType grantType;
		if (isEmptyString(grantTypeS)) {
			grantType = AUTHORIZATION_CODE;
		} else {
			try {
				grantType = GrantType.valueOf(grantTypeS.toUpperCase());
			} catch (Exception e) {
				throw new UnsupportedGrantTypeException(MessageFormat.format("Unsupported grant type '{0}'", grantTypeS));
			}
		}

		final String authCode = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_CODE);
		final String refreshToken = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_REFRESH_TOKEN);
		final String username = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_USERNAME);
		final String password = OAuthWebServerUtil.getOnlyOneParameter(req, OAuth20.OAUTH_PASSWORD);
		final List<String> scopes = OAuthWebServerUtil.parseScopes(req);
		try {
			return new TokenRequest(grantType, clientId, clientSecret, redirectUri, authCode, refreshToken, username, password, scopes);
		} catch (IllegalArgumentException e) {
			throw new InvalidRequestException(e.getMessage());
		}
	}

}
