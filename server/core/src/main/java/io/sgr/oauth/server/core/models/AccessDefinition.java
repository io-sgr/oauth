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

import java.io.Serializable;
import java.util.Collection;

public class AccessDefinition implements Serializable {

	private final String clientId;
	private final String userId;
	private final Collection<String> scopes;
	private final String redirectUri;

	public AccessDefinition(final String clientId, final String userId, final Collection<String> scopes, final String redirectUri) {
		notEmptyString(clientId, "Client ID needs to be specified");
		this.clientId = clientId;
		notEmptyString(userId, "User ID needs to be specified");
		this.userId = userId;
		notNull(scopes, "Scopes needs to be specified");
		if (scopes.isEmpty()) {
			throw new IllegalArgumentException("Scopes needs to be specified");
		}
		this.scopes = scopes;
		notEmptyString(redirectUri, "Redirect URI needs to be specified");
		this.redirectUri = redirectUri;
	}

	public String getClientId() {
		return clientId;
	}

	public String getUserId() {
		return userId;
	}

	public Collection<String> getScopes() {
		return scopes;
	}

	public String getRedirectUri() {
		return redirectUri;
	}
}
