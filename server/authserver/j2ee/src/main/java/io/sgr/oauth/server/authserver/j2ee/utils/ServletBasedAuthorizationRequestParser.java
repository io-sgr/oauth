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
import static io.sgr.oauth.server.authserver.j2ee.utils.OAuthWebServerUtil.getOnlyOneParameter;

import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.UnsupportedResponseTypeException;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.AuthRequestParser;
import io.sgr.oauth.server.core.models.AuthorizationRequest;

import java.text.MessageFormat;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

public class ServletBasedAuthorizationRequestParser implements AuthRequestParser<HttpServletRequest> {

	private static final ServletBasedAuthorizationRequestParser INSTANCE = new ServletBasedAuthorizationRequestParser();

	private ServletBasedAuthorizationRequestParser() {

	}

	public static ServletBasedAuthorizationRequestParser instance() {
		return INSTANCE;
	}

	@Override public AuthorizationRequest parse(final HttpServletRequest req)
			throws InvalidRequestException, UnsupportedResponseTypeException {
		notNull(req, "Missing HttpServletRequest");
		final String responseTypeS = getOnlyOneParameter(req, OAuth20.OAUTH_RESPONSE_TYPE).orElse(null);
		final ResponseType responseType;
		if (isEmptyString(responseTypeS)) {
			responseType = ResponseType.CODE;
		} else {
			try {
				responseType = ResponseType.valueOf(responseTypeS.toUpperCase());
			} catch (Exception e) {
				throw new UnsupportedResponseTypeException(MessageFormat.format("Unsupported response type '{0}'", responseTypeS));
			}
		}
		final String clientId = getOnlyOneParameter(req, OAuth20.OAUTH_CLIENT_ID).orElse(null);
		final String redirectUri = getOnlyOneParameter(req, OAuth20.OAUTH_REDIRECT_URI).orElse(null);
		final List<String> scopes = OAuthWebServerUtil.parseScopes(req).orElse(null);
		final String state = getOnlyOneParameter(req, OAuth20.OAUTH_STATE).orElse(null);
		try {
			return new AuthorizationRequest(responseType, clientId, redirectUri, scopes, state);
		} catch (IllegalArgumentException e) {
			throw new InvalidRequestException(e.getMessage());
		}
	}

}
