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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author SgrAlpha
 *
 */
public class OAuthServerUtil {

	public static boolean isRedirectUriRegistered(final String redirectUri, final Collection<String> callbacks) {
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		notNull(callbacks, "Registered callbacks needs to be specified");
		return isRedirectUriRegistered(redirectUri, new HashSet<>(callbacks));
	}

	public static boolean isRedirectUriRegistered(final String redirectUri, final Set<String> callbacks) {
		notNull(callbacks, "Registered callbacks needs to be specified");
		return callbacks.contains(toBaseEndpoint(redirectUri));
	}

	public static String toBaseEndpoint(final String redirectUri) {
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		try {
			final URI uri = URI.create(URLDecoder.decode(redirectUri, "UTF-8"));
			return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), null, null).toString();
		} catch (URISyntaxException | UnsupportedEncodingException e) {
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
