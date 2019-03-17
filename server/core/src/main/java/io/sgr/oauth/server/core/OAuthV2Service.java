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

    void createScope(ScopeDefinition scope);

    void updateScope(ScopeDefinition scope);

    void deleteScope(String id);

    Optional<ScopeDefinition> getScopeById(String id, Locale locale);

    void createOAuthClient(OAuthClientInfo client);

    void updateOAuthClient(OAuthClientInfo client);

    void deleteOAuthClient(String clientId);

    Optional<OAuthClientInfo> getOAuthClientById(String clientId);

    Optional<OAuthClientInfo> getOAuthClientByIdAndSecret(String clientId, String clientSecret);

    boolean checkIfUserAuthorized(String currentUser, String clientId, List<String> requestedScopes);

    boolean isAuthorizationCodeRevoked(String authCode);

    void revokeAuthorizationCode(String authCode);

    Collection<String> getGrantedScopes(String clientId, String userId);

    OAuthCredential generateAccessToken(String clientId, String userId, Collection<String> scopes);

    String getUserIdByUsernameAndPassword(String username, String password);

    boolean isValidRefreshToken(String clientId, String refreshToken);

    OAuthCredential refreshAccessToken(String clientId, String refreshToken);

}
