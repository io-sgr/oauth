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

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.AuthorizationServer;
import io.sgr.oauth.server.core.OAuthV2Service;
import io.sgr.oauth.server.core.exceptions.InvalidClientException;
import io.sgr.oauth.server.core.exceptions.InvalidGrantException;
import io.sgr.oauth.server.core.exceptions.InvalidRequestException;
import io.sgr.oauth.server.core.exceptions.InvalidScopeException;
import io.sgr.oauth.server.core.exceptions.UnsupportedGrantTypeException;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class GenericOAuthV2TokenServlet extends HttpServlet {

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final Optional<OAuthCredential> credential;
		try {
			credential = AuthorizationServer.with(getOAuthV2Service()).build().generateToken(req);
		} catch (InvalidRequestException | InvalidGrantException | InvalidScopeException | UnsupportedGrantTypeException e) {
			onBadOAuthRequest(req, resp, e.getError());
			return;
		} catch (InvalidClientException e) {
			onUnauthorizedRequest(req, resp, e.getError());
			return;
		}

		if (!credential.isPresent()) {
			resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to create OAuth token");
			return;
		}
		resp.setContentType("application/json;charset=UTF-8");
		resp.setCharacterEncoding("UTF-8");
		resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(credential));
	}

	protected abstract void onBadOAuthRequest(final HttpServletRequest req, final HttpServletResponse resp, final OAuthError error) throws ServletException, IOException;

	protected abstract void onUnauthorizedRequest(final HttpServletRequest req, final HttpServletResponse resp, final OAuthError error) throws ServletException, IOException;

	protected abstract OAuthV2Service getOAuthV2Service();

}
