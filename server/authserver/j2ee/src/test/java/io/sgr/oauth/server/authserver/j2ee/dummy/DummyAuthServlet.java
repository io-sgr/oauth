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

package io.sgr.oauth.server.authserver.j2ee.dummy;

import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.server.authserver.core.AuthorizationDetail;
import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.GenericOAuthV2AuthServlet;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet
public class DummyAuthServlet extends GenericOAuthV2AuthServlet {

    private AuthorizationServer authServer;
    private DummyBackend backend;

    public DummyAuthServlet(final AuthorizationServer authServer, final DummyBackend backend) {
        this.authServer = authServer;
        this.backend = backend;
    }

    @Override
    protected String getCurrentUserId(final HttpServletRequest req, final HttpServletResponse resp) {
        return backend.getCurrentUserId();
    }

    @Override
    protected Locale getUserLocale(final HttpServletRequest req, final HttpServletResponse resp) {
        return backend.getUserLocale();
    }

    @Override
    protected void onUserNotSignedIn(final HttpServletRequest req, final HttpServletResponse resp) {
        backend.onUserNotSignedIn();
    }

    @Override
    protected void onBadOAuthRequest(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) {
        backend.onBadOAuthRequest(error);
    }

    @Override
    protected void onInvalidClient(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        backend.onInvalidClient(error);
    }

    @Override
    protected void onServerError(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) {
        backend.onServerError(error);
    }

    @Override
    protected void displayUserAuthorizePage(final AuthorizationDetail authDetail, final HttpServletRequest req, final HttpServletResponse resp) {
        backend.displayUserAuthorizePage(authDetail);
    }

    @Override
    protected AuthorizationServer getAuthorizationServer() {
        return authServer;
    }

}
