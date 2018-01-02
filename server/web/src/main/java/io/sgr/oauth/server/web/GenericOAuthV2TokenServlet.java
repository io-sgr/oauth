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

package io.sgr.oauth.server.web;

import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.core.OAuthV2Service;
import io.sgr.oauth.server.core.exceptions.BadOAuthTokenRequestException;
import io.sgr.oauth.server.core.models.AccessDefinition;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.TokenRequest;
import io.sgr.oauth.server.core.utils.OAuthServerUtil;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class GenericOAuthV2TokenServlet extends HttpServlet {

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final TokenRequest tokenReq;
		try {
			tokenReq = OAuthServerUtil.parseTokenRequest(req);
		} catch (BadOAuthTokenRequestException e) {
			onBadOAuthRequest(req, resp, e.getError());
			return;
		}

		final AccessDefinition accessDef = getOAuthV2Service().getOAuthAccessDefinitionByAuthCode(tokenReq.getCode());
		if (accessDef == null || !accessDef.getClientId().equals(tokenReq.getClientId())) {
			onUnauthorizedRequest(req, resp, new OAuthError("unauthorized_code", "Unauthorized code.", null));
			return;
		}
		final Optional<OAuthClientInfo> clientInfo = getOAuthV2Service().getOAuthClientByIdAndSecret(tokenReq.getClientId(), tokenReq.getClientSecret());
		if (!clientInfo.isPresent()) {
			onUnauthorizedRequest(req, resp, new OAuthError("unauthorized_client", "Unauthorized OAuth client.", null));
			return;
		}
	}

	protected abstract void onBadOAuthRequest(final HttpServletRequest req, final HttpServletResponse resp, final OAuthError error);

	protected abstract void onUnauthorizedRequest(final HttpServletRequest req, final HttpServletResponse resp, final OAuthError error);

	protected abstract OAuthV2Service getOAuthV2Service();

}
