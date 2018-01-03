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

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.server.web.utils.OAuthV2WebConstants.REQ_PARAMS_KEY_APPROVED;
import static io.sgr.oauth.server.web.utils.OAuthV2WebConstants.REQ_PARAMS_KEY_CSRF_TOKEN;
import static io.sgr.oauth.server.web.utils.OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_CODE_REQ;
import static io.sgr.oauth.server.web.utils.OAuthV2WebConstants.SESSION_ATTRS_KEY_CLIENT_INFO;
import static io.sgr.oauth.server.web.utils.OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN;
import static io.sgr.oauth.server.web.utils.OAuthV2WebConstants.SESSION_ATTRS_KEY_SCOPES;

import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.OAuthV2Service;
import io.sgr.oauth.server.core.exceptions.BadOAuthRequestException;
import io.sgr.oauth.server.core.models.AccessDefinition;
import io.sgr.oauth.server.core.models.AuthorizationCodeRequest;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;
import io.sgr.oauth.server.core.utils.OAuthServerUtil;

import java.io.IOException;
import java.net.URI;
import java.text.MessageFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;

public abstract class GenericOAuthV2AuthServlet extends HttpServlet {

	@Override protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final String curUserId = getCurrentUserId(req, resp);
		if (isEmptyString(curUserId)) {
			onUserNotSignedIn(req, resp);
			return;
		}

		final AuthorizationCodeRequest oauthReq;
		try {
			oauthReq = OAuthServerUtil.parseAuthorizationCodeRequest(req);
		} catch (BadOAuthRequestException e) {
			onBadOAuthRequest(req, resp, e.getError());
			return;
		}

		final ResponseType responseType = oauthReq.getResponseType();
		switch (responseType) {
			case CODE:
				break;
			default:
				onBadOAuthRequest(req, resp, new OAuthError("unsupported_response_type", MessageFormat.format("Unsupported response type '{0}'.", responseType)));
				return;
		}
		final String clientId = oauthReq.getClientId();
		final String redirectUri = oauthReq.getRedirectUri();
		final Optional<OAuthClientInfo> clientInfo = getOAuthV2Service().getOAuthClientById(clientId);
		if (!clientInfo.isPresent()) {
			onBadOAuthRequest(req, resp, new OAuthError("unknown_client_id", "Unknown OAuth client."));
			return;
		}
		final List<String> callbacks = clientInfo.map(OAuthClientInfo::getCallbacks).orElse(null);
		if (!OAuthServerUtil.isRedirectUriRegistered(redirectUri, callbacks)) {
			onBadOAuthRequest(req, resp, new OAuthError("redirect_uri_mismatch", MessageFormat.format("OAuth client redirect URI mismatch: {0}", redirectUri)));
			return;
		}

		final String[] names = oauthReq.getScopes().split(",");
		if (names.length == 0 ) {
			onBadOAuthRequest(req, resp, new OAuthError("missing_scope", "Missing OAuth client request scopes."));
			return;
		}

		final List<ScopeDefinition> checkedScopes = new LinkedList<>();
		for (String name : names) {
			if (isEmptyString(name)) {
				continue;
			}
			Optional<ScopeDefinition> scope = getOAuthV2Service().getScopeByName(name);
			if (!scope.isPresent()) {
				onBadOAuthRequest(req, resp, new OAuthError("unknown_scope", MessageFormat.format("Unknown OAuth request scope: {0}", name)));
				return;
			}
			checkedScopes.add(scope.get());
		}

		final HttpSession session = req.getSession(true);
		session.setAttribute(SESSION_ATTRS_KEY_AUTH_CODE_REQ, oauthReq);
		session.setAttribute(SESSION_ATTRS_KEY_CLIENT_INFO, clientInfo.get());
		session.setAttribute(SESSION_ATTRS_KEY_SCOPES, checkedScopes);
		session.setAttribute(SESSION_ATTRS_KEY_CSRF_TOKEN, UUID.randomUUID().toString().replaceAll("-", ""));
		onDisplayUserAuthorizePage(oauthReq, clientInfo.get(), checkedScopes, req, resp);
	}

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final String currentUserId = getCurrentUserId(req, resp);
		if (isEmptyString(currentUserId)) {
			onUserNotSignedIn(req, resp);
			return;
		}

		final HttpSession session = req.getSession(true);

		final String reqCsrfToken = req.getParameter(REQ_PARAMS_KEY_CSRF_TOKEN);
		if (isEmptyString(reqCsrfToken) || !session.getAttribute(SESSION_ATTRS_KEY_CSRF_TOKEN).equals(reqCsrfToken)) {
			onBadOAuthRequest(req, resp, new OAuthError("csrf_token_mismatch", "CSRF token mismatch!"));
			return;
		}
		session.removeAttribute(SESSION_ATTRS_KEY_CSRF_TOKEN);

		final AuthorizationCodeRequest oauthReq = (AuthorizationCodeRequest) session.getAttribute(SESSION_ATTRS_KEY_AUTH_CODE_REQ);
		if (oauthReq == null) {
			onBadOAuthRequest(req, resp, new OAuthError("bad_oauth_request", "Bad OAuth request"));
			return;
		}
		final ResponseType responseType = oauthReq.getResponseType();
		final String redirectUri = oauthReq.getRedirectUri();
		final String state = oauthReq.getState();
		final OAuthClientInfo clientInfo = (OAuthClientInfo) session.getAttribute(SESSION_ATTRS_KEY_CLIENT_INFO);
		if (clientInfo == null) {
			onBadOAuthRequest(req, resp, new OAuthError("bad_oauth_request", "Missing OAuth client info"));
			return;
		}
		final List<?> scopes = (List<?>) session.getAttribute(SESSION_ATTRS_KEY_SCOPES);
		if (scopes == null || scopes.isEmpty()) {
			onBadOAuthRequest(req, resp, new OAuthError("bad_oauth_request", "Missing scopes"));
			return;
		}
		List<String> checkedScopes = scopes.parallelStream()
				.filter(ScopeDefinition.class::isInstance)
				.map(scope -> ((ScopeDefinition) scope).getName())
				.collect(Collectors.toList());
		if (checkedScopes.isEmpty()) {
			onBadOAuthRequest(req, resp, new OAuthError("bad_oauth_request", "Missing scopes"));
			return;
		}

		final String approvedS = req.getParameter(REQ_PARAMS_KEY_APPROVED);
		final boolean approved = !isEmptyString(approvedS) && Boolean.parseBoolean(approvedS);

		final UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
		if (!isEmptyString(state)) {
			uriBuilder.queryParam(OAuth20.OAUTH_STATE, state);
		}
		final URI uri;
		if (approved) {
			switch (responseType) {
				case CODE:
					final String code = UUID.randomUUID().toString().replaceAll("-", "");
					getOAuthV2Service().createOAuthAccessDefinition(code, new AccessDefinition(clientInfo.getId(), currentUserId, checkedScopes, redirectUri));
					uri = uriBuilder.queryParam(OAuth20.OAUTH_CODE, code).build();
					break;
				default:
					onBadOAuthRequest(req, resp, new OAuthError("unsupported_response_type", MessageFormat.format("Unsupported response type '{0}'.", responseType)));
					return;
			}
		} else {
			uri = uriBuilder.queryParam("error", "user_declined").build();
		}

		session.removeAttribute(SESSION_ATTRS_KEY_AUTH_CODE_REQ);
		session.removeAttribute(SESSION_ATTRS_KEY_CLIENT_INFO);
		session.removeAttribute(SESSION_ATTRS_KEY_SCOPES);

		resp.setHeader("Location", uri.toString());
		resp.sendError(HttpServletResponse.SC_MOVED_TEMPORARILY);
	}

	protected abstract String getCurrentUserId(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException;

	protected abstract void onUserNotSignedIn(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException;

	protected abstract void onBadOAuthRequest(final HttpServletRequest req, final HttpServletResponse resp, final OAuthError error) throws ServletException, IOException;

	protected abstract void onDisplayUserAuthorizePage(final AuthorizationCodeRequest oauthReq, final OAuthClientInfo oAuthClientInfo, final List<ScopeDefinition> checkedScopes, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException;

	protected abstract OAuthV2Service getOAuthV2Service();

}
