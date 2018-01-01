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

package io.sgr.oauth.server.core;

import io.sgr.oauth.server.core.models.AccessDefinition;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;

import java.util.Optional;

public interface OAuthV2Service {

	void createScope(final ScopeDefinition scope);

	void updateScope(final ScopeDefinition scope);

	void deleteScope(final String name);

	Optional<ScopeDefinition> getScopeByName(final String name);

	void createOAuthClient(final OAuthClientInfo client);

	void updateOAuthClient(final OAuthClientInfo client);

	void deleteOAuthClient(final String clientId);

	Optional<OAuthClientInfo> getOAuthClientById(final String clientId);

	Optional<OAuthClientInfo> getOAuthClientByIdAndSecret(final String clientId, final String clientSecret);

	void createOAuthAccessDefinition(final String authCode, final AccessDefinition accessDefinition);

	AccessDefinition getOAuthAccessDefinitionByAuthCode(final String authCode);

}
