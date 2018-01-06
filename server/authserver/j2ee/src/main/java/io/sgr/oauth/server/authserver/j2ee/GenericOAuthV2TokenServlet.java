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

import io.sgr.oauth.authserver.core.AuthorizationServer;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.ServerErrorException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.core.v20.OAuthErrorType;
import io.sgr.oauth.server.authserver.j2ee.utils.ServletBasedTokenRequestParser;
import io.sgr.oauth.server.core.OAuthV2Service;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class GenericOAuthV2TokenServlet extends HttpServlet {

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
		resp.setContentType("application/json;charset=UTF-8");
		resp.setCharacterEncoding("UTF-8");
		final Optional<OAuthCredential> credential;
		try {
			credential = AuthorizationServer.with(getOAuthV2Service()).build()
					.generateToken(req, ServletBasedTokenRequestParser.instance());
		} catch (InvalidRequestException | InvalidGrantException | InvalidScopeException | UnsupportedGrantTypeException e) {
			resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(e.getError()));
			return;
		} catch (InvalidClientException e) {
			resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(e.getError()));
			return;
		} catch (ServerErrorException e) {
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(e.getError()));
			return;
		}

		if (!credential.isPresent()) {
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			final OAuthError error = new OAuthError(OAuthErrorType.SERVER_ERROR.name().toLowerCase(), "Unable to create OAuth token");
			resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(error));
			return;
		}
		resp.getWriter().write(JsonUtil.getObjectMapper().writeValueAsString(credential));
	}

	protected abstract OAuthV2Service getOAuthV2Service();

}
