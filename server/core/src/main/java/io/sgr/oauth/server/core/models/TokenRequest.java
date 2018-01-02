/*
 * Copyright 2018 SgrAlpha
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

package io.sgr.oauth.server.core.models;

import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.sgr.oauth.core.v20.GrantType;

import java.io.Serializable;

public class TokenRequest implements Serializable {

	private final String clientId;
	private final String clientSecret;
	private final String redirectUri;
	private final GrantType grantType;
	private final String code;
	private final String refreshToken;
	private final String username;
	private final String password;

	public TokenRequest(final String clientId, final String clientSecret, final String redirectUri,
	                    final GrantType grantType,
	                    final String code, final String refreshToken,
	                    final String username, final String password) {
		notEmptyString(clientId, "Client ID needs to be specified");
		this.clientId = clientId;
		notEmptyString(clientSecret, "Client secret needs to be specified");
		this.clientSecret = clientSecret;
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		this.redirectUri = redirectUri;
		notNull(grantType, "Grant type needs to be specified");
		this.grantType = grantType;
		this.code = code;
		this.refreshToken = refreshToken;
		this.username = username;
		this.password = password;
		switch (grantType) {
			case AUTHORIZATION_CODE:
				notEmptyString(code, "Authorization code needs to be specified");
				break;
			case REFRESH_TOKEN:
				notEmptyString(refreshToken, "Refresh token needs to be specified");
				break;
			case PASSWORD:
				notEmptyString(username, "Username needs to be specified");
				notEmptyString(password, "Password needs to be specified");
				break;
			default:
				break;
		}
	}

	public String getClientId() {
		return clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public GrantType getGrantType() {
		return grantType;
	}

	public String getCode() {
		return code;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}
}
