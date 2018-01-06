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

package io.sgr.oauth.server.core.models;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.sgr.oauth.core.v20.ResponseType;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class AuthorizationRequest implements Serializable {

	private final ResponseType responseType;
	private final String clientId;
	private final String redirectUri;
	private final List<String> scopes;
	private final String state;

	/**
	 * @param responseType The response type
	 * @param clientId     The client ID
	 * @param redirectUri  The redirect URI
	 * @param scopes       The scopes
	 * @param state        The state
	 */
	public AuthorizationRequest(
			final ResponseType responseType, final String clientId, final String redirectUri, final List<String> scopes,
			final String state) {
		notNull(responseType, "Response type needs to be specified");
		this.responseType = responseType;
		notEmptyString(clientId, "Client ID needs to be specified");
		this.clientId = clientId;
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		this.redirectUri = redirectUri;
		notNull(scopes, "Scopes need to be specified");
		this.scopes = scopes;
		this.state = isEmptyString(state) ? null : state;
	}

	/**
	 * @return The response type
	 */
	public ResponseType getResponseType() {
		return responseType;
	}

	/**
	 * @return The client ID
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * @return The redirect URI
	 */
	public String getRedirectUri() {
		return redirectUri;
	}

	/**
	 * @return The scopes
	 */
	public List<String> getScopes() {
		return Collections.unmodifiableList(scopes);
	}

	/**
	 * @return The state
	 */
	public Optional<String> getState() {
		return Optional.ofNullable(state);
	}
}
