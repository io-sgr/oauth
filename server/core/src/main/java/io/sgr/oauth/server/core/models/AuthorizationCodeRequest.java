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

package io.sgr.oauth.server.core.models;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.sgr.oauth.core.v20.ResponseType;

import java.io.Serializable;

public class AuthorizationCodeRequest implements Serializable {

	private final ResponseType responseType;
	private final String clientId;
	private final String redirectUri;
	private final String scopes;
	private final String state;

	public AuthorizationCodeRequest(final ResponseType responseType, final String clientId, final String redirectUri, final String scopes, final String state) {
		notNull(responseType, "Response type needs to be specified");
		this.responseType = responseType;
		notEmptyString(clientId, "Client ID needs to be specified");
		this.clientId = clientId;
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		this.redirectUri = redirectUri;
		notEmptyString(scopes, "Request scope needs to be specified");
		this.scopes = scopes;
		this.state = isEmptyString(state) ? null : state;
	}

	public ResponseType getResponseType() {
		return responseType;
	}

	public String getClientId() {
		return clientId;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public String getScopes() {
		return scopes;
	}

	public String getState() {
		return state;
	}
}
