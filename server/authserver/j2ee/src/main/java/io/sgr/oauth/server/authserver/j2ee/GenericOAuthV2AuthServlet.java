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

package io.sgr.oauth.server.authserver.j2ee;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;

import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.ServerErrorException;
import io.sgr.oauth.core.exceptions.UnsupportedResponseTypeException;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.authserver.core.AuthorizationDetail;
import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.utils.OAuthV2WebConstants;
import io.sgr.oauth.server.authserver.j2ee.utils.ServletBasedAuthorizationRequestParser;

import java.io.IOException;
import java.util.Locale;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public abstract class GenericOAuthV2AuthServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        final String curUserId = getCurrentUserId(req, resp);
        if (isEmptyString(curUserId)) {
            onUserNotSignedIn(req, resp);
            return;
        }

        final AuthorizationDetail authDetail;
        try {
            authDetail = getAuthorizationServer()
                    .preAuthorization(req, ServletBasedAuthorizationRequestParser.instance(), curUserId, getUserLocale(req, resp));
            if (authDetail == null) {
                throw new ServerErrorException("Unable to check authorization request");
            }
        } catch (InvalidClientException e) {
            onInvalidClient(e.getError(), req, resp);
            return;
        } catch (InvalidRequestException | InvalidScopeException | UnsupportedResponseTypeException e) {
            onBadOAuthRequest(e.getError(), req, resp);
            return;
        } catch (ServerErrorException e) {
            onServerError(e.getError(), req, resp);
            return;
        }

        if (authDetail.isAlreadyAuthorized()) {
            afterAuthorized(true, authDetail, req, resp);
            return;
        }

        final HttpSession session = req.getSession(true);
        session.setAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_DETAIL, authDetail);
        session.setAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN, UUID.randomUUID().toString().replaceAll("-", ""));
        displayUserAuthorizePage(authDetail, req, resp);
    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        final String currentUserId = getCurrentUserId(req, resp);
        if (isEmptyString(currentUserId)) {
            onUserNotSignedIn(req, resp);
            return;
        }

        final HttpSession session = req.getSession(true);

        final String reqCsrfToken = req.getParameter(OAuthV2WebConstants.REQ_PARAMS_KEY_CSRF_TOKEN);
        if (isEmptyString(reqCsrfToken) || !reqCsrfToken.equals(session.getAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN))) {
            session.removeAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN);
            onBadOAuthRequest(new OAuthError("csrf_token_mismatch", "CSRF token mismatch!"), req, resp);
            return;
        }
        session.removeAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_CSRF_TOKEN);

        final Object detail = session.getAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_DETAIL);
        if (!(detail instanceof AuthorizationDetail)) {
            session.removeAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_DETAIL);
            onBadOAuthRequest(new OAuthError("bad_oauth_request", "Bad OAuth request"), req, resp);
            return;
        }
        session.removeAttribute(OAuthV2WebConstants.SESSION_ATTRS_KEY_AUTH_DETAIL);

        final String approvedS = req.getParameter(OAuthV2WebConstants.REQ_PARAMS_KEY_APPROVED);
        final boolean approved = !isEmptyString(approvedS) && Boolean.parseBoolean(approvedS);

        final AuthorizationDetail authDetail = (AuthorizationDetail) detail;

        afterAuthorized(approved, authDetail, req, resp);
    }

    private void afterAuthorized(final boolean approved, final AuthorizationDetail authDetail, final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        final String location;
        try {
            location = getAuthorizationServer().postAuthorization(approved, authDetail);
            if (isEmptyString(location)) {
                throw new ServerErrorException("Unable to authorize");
            }
        } catch (UnsupportedResponseTypeException e) {
            onBadOAuthRequest(e.getError(), req, resp);
            return;
        } catch (ServerErrorException e) {
            onServerError(e.getError(), req, resp);
            return;
        }

        resp.setHeader("Location", location);
        resp.sendError(HttpServletResponse.SC_MOVED_TEMPORARILY);
    }

    protected abstract void displayUserAuthorizePage(AuthorizationDetail authDetail, HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException;

    protected abstract String getCurrentUserId(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;

    protected abstract Locale getUserLocale(HttpServletRequest req, HttpServletResponse resp);

    protected abstract void onUserNotSignedIn(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;

    protected abstract void onBadOAuthRequest(OAuthError error, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;

    protected abstract void onInvalidClient(OAuthError error, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;

    protected abstract void onServerError(OAuthError error, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException;

    protected abstract AuthorizationServer getAuthorizationServer();

}
