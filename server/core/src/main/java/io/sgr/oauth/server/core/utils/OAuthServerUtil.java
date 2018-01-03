/*
 * Copyright 2017 SgrAlpha
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
package io.sgr.oauth.server.core.utils;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.exceptions.BadOAuthRequestException;
import io.sgr.oauth.server.core.models.AuthorizationCodeRequest;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

/**
 * @author SgrAlpha
 *
 */
public class OAuthServerUtil {

	public static AuthorizationCodeRequest parseAuthorizationCodeRequest(final HttpServletRequest req)
			throws BadOAuthRequestException {
		notNull(req, "Missing HTTP servlet request");
		final String responseTypeS = req.getParameter(OAuth20.OAUTH_RESPONSE_TYPE);
		final ResponseType responseType;
		if (isEmptyString(responseTypeS)) {
			responseType = ResponseType.CODE;
		} else {
			try {
				responseType = ResponseType.valueOf(responseTypeS.toUpperCase());
			} catch (Exception e) {
				throw new BadOAuthRequestException(MessageFormat.format("Invalid response type '{0}'", responseTypeS));
			}
		}
		final String clientId = req.getParameter(OAuth20.OAUTH_CLIENT_ID);
		if (isEmptyString(clientId)) {
			throw new BadOAuthRequestException("Missing client ID");
		}
		String redirectUri = req.getParameter(OAuth20.OAUTH_REDIRECT_URI);
		if (isEmptyString(redirectUri)) {
			throw new BadOAuthRequestException("Missing client redirect URI");
		}
		try {
			redirectUri = URLDecoder.decode(redirectUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		String scopes = req.getParameter(OAuth20.OAUTH_SCOPE);
		if (isEmptyString(scopes)) {
			throw new BadOAuthRequestException("Missing client request scopes");
		}
		try {
			scopes = URLDecoder.decode(scopes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		scopes = scopes.replaceAll(" ", "");
		final String state = req.getParameter(OAuth20.OAUTH_STATE);
		return new AuthorizationCodeRequest(responseType, clientId, redirectUri, scopes, state);
	}

	public static boolean isRedirectUriRegistered(final String redirectUri, final String... callbacks) {
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		return callbacks != null && callbacks.length == 0 && isRedirectUriRegistered(redirectUri, new HashSet<>(Arrays.asList(callbacks)));
	}

	public static boolean isRedirectUriRegistered(final String redirectUri, final List<String> callbacks) {
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		return callbacks != null && !callbacks.isEmpty() && isRedirectUriRegistered(redirectUri, new HashSet<>(callbacks));
	}

	public static boolean isRedirectUriRegistered(final String redirectUri, final Set<String> callbacks) {
		return callbacks != null && !callbacks.isEmpty() && callbacks.contains(toBaseEndpoint(redirectUri));
	}

	public static String toBaseEndpoint(final String redirectUri) {
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		try {
			final URI uri = URI.create(redirectUri);
			return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), null, null).toString();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	public static OAuthCredential parseAccessTokenFromAuthorization(String authStr) {
		if (isEmptyString(authStr)) {
			return null;
		}
		String[] a = authStr.split(" ");
		if (a.length != 2) {
			return null;
		}
		return new OAuthCredential(a[1], a[0]);
	}

}
