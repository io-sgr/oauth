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

package io.sgr.oauth.server.core;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public interface OAuthV2Service {

	void createScope(final ScopeDefinition scope);

	void updateScope(final ScopeDefinition scope);

	void deleteScope(final String id);

	Optional<ScopeDefinition> getScopeById(final String id, final Locale locale);

	void createOAuthClient(final OAuthClientInfo client);

	void updateOAuthClient(final OAuthClientInfo client);

	void deleteOAuthClient(final String clientId);

	Optional<OAuthClientInfo> getOAuthClientById(final String clientId);

	Optional<OAuthClientInfo> getOAuthClientByIdAndSecret(final String clientId, final String clientSecret);

	boolean checkIfUserAuthorized(final String currentUser, final String clientId, final List<String> requestedScopes);

	boolean isAuthorizationCodeRevoked(final String authCode);

	void revokeAuthorizationCode(final String authCode);

	Collection<String> getGrantedScopes(final String clientId, final String userId);

	OAuthCredential generateAccessToken(final String clientId, final String userId, final Collection<String> scopes);

	String getUserIdByUsernameAndPassword(final String username, final String password);

	boolean isValidRefreshToken(final String clientId, final String refreshToken);

	OAuthCredential refreshAccessToken(final String clientId, final String refreshToken);

}
