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

package io.sgr.oauth.server.authserver.core;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationDetail implements Serializable {

	private final ResponseType responseType;
	private final OAuthClientInfo client;
	private final String currentUser;
	private final List<ScopeDefinition> scopes;
	private final String redirectUri;
	private final String state;
	private final boolean alreadyAuthorized;

	/**
	 * @param responseType      The response type
	 * @param client            The client
	 * @param currentUser       Current user
	 * @param redirectUri       The redirect URI
	 * @param scopes            The scopes
	 * @param state             Optional. The state of request, default to null
	 * @param alreadyAuthorized User already authorized or not
	 */
	@JsonCreator
	public AuthorizationDetail(
			@JsonProperty(OAuth20.OAUTH_RESPONSE_TYPE) final ResponseType responseType,
			@JsonProperty("client") final OAuthClientInfo client,
			@JsonProperty("current_user") final String currentUser,
			@JsonProperty(OAuth20.OAUTH_REDIRECT_URI) final String redirectUri,
			@JsonProperty("scopes") final List<ScopeDefinition> scopes,
			@JsonProperty(OAuth20.OAUTH_STATE) final String state,
			@JsonProperty("already_authorized") final boolean alreadyAuthorized) {
		notNull(responseType, "Missing response type");
		this.responseType = responseType;
		notNull(client, "Missing client info");
		this.client = client;
		notEmptyString(currentUser, "Missing current user");
		this.currentUser = currentUser;
		notEmptyString(redirectUri, "Missing redirect URI");
		try {
			this.redirectUri = URLDecoder.decode(redirectUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		notNull(scopes, "Missing scopes");
		if (scopes.isEmpty()) {
			throw new IllegalArgumentException("Missing scopes");
		}
		this.scopes = scopes;
		this.state = isEmptyString(state) ? null : state;
		this.alreadyAuthorized = alreadyAuthorized;
	}

	/**
	 * @return The response type
	 */
	@JsonProperty(OAuth20.OAUTH_RESPONSE_TYPE)
	public ResponseType getResponseType() {
		return responseType;
	}

	/**
	 * @return The client ID
	 */
	@JsonProperty("client")
	public OAuthClientInfo getClient() {
		return client;
	}

	/**
	 * @return The current user
	 */
	@JsonProperty("current_user")
	public String getCurrentUser() {
		return currentUser;
	}

	/**
	 * @return The redirect URI
	 */
	@JsonProperty(OAuth20.OAUTH_REDIRECT_URI)
	public String getRedirectUri() {
		return redirectUri;
	}

	/**
	 * @return The scopes
	 */
	@JsonProperty("scopes")
	public List<ScopeDefinition> getScopes() {
		return Collections.unmodifiableList(scopes);
	}

	/**
	 * @return The state
	 */
	@JsonProperty(OAuth20.OAUTH_STATE)
	public Optional<String> getState() {
		return Optional.ofNullable(state);
	}

	/**
	 * @return User already authorized or not
	 */
	public boolean isAlreadyAuthorized() {
		return alreadyAuthorized;
	}
}
