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

package io.sgr.oauth.server.authserver.j2ee;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.ServerErrorException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.utils.ServletBasedTokenRequestParser;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class GenericOAuthV2TokenServlet extends HttpServlet {

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		resp.setContentType("application/json;charset=UTF-8");
		resp.setCharacterEncoding("UTF-8");
		final OAuthCredential credential;
		try {
			credential = getAuthorizationServer().generateToken(req, ServletBasedTokenRequestParser.instance());
			if (credential == null) {
				throw new ServerErrorException("Unable to generate access token");
			}
		} catch (InvalidRequestException | InvalidGrantException | InvalidScopeException | UnsupportedGrantTypeException e) {
			onBadTokenRequest(e.getError(), req, resp);
			return;
		} catch (InvalidClientException e) {
			onInvalidClient(e.getError(), req, resp);
			return;
		} catch (ServerErrorException e) {
			onServerError(e.getError(), req, resp);
			return;
		}
		resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(credential));
	}

	protected abstract void onBadTokenRequest(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException;

	protected abstract void onInvalidClient(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException;

	protected abstract void onServerError(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException;

	protected abstract AuthorizationServer getAuthorizationServer();

}
