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

package io.sgr.oauth.server.authserver.j2ee.utils;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;
import static io.sgr.oauth.core.v20.GrantType.AUTHORIZATION_CODE;
import static io.sgr.oauth.server.authserver.j2ee.utils.OAuthWebServerUtil.getOnlyOneParameter;
import static io.sgr.oauth.server.authserver.j2ee.utils.OAuthWebServerUtil.parseScopes;

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
		final String grantTypeS = getOnlyOneParameter(req, OAuth20.OAUTH_GRANT_TYPE).orElse(null);
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
		final String clientId = getOnlyOneParameter(req, OAuth20.OAUTH_CLIENT_ID).orElse(null);
		final String clientSecret = getOnlyOneParameter(req, OAuth20.OAUTH_CLIENT_SECRET).orElse(null);
		final String redirectUri = getOnlyOneParameter(req, OAuth20.OAUTH_REDIRECT_URI).orElse(null);
		final String authCode = getOnlyOneParameter(req, OAuth20.OAUTH_CODE).orElse(null);
		final String refreshToken = getOnlyOneParameter(req, OAuth20.OAUTH_REFRESH_TOKEN).orElse(null);
		final String username = getOnlyOneParameter(req, OAuth20.OAUTH_USERNAME).orElse(null);
		final String password = getOnlyOneParameter(req, OAuth20.OAUTH_PASSWORD).orElse(null);
		final List<String> scopes = parseScopes(req).orElse(null);
		try {
			return new TokenRequest(grantType, clientId, clientSecret, redirectUri, authCode, refreshToken, username, password, scopes);
		} catch (IllegalArgumentException e) {
			throw new InvalidRequestException(e.getMessage());
		}
	}

}
