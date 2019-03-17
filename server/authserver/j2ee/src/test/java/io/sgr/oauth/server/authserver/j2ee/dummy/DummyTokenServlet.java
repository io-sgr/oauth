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
import io.sgr.oauth.server.authserver.core.AuthorizationServer;
import io.sgr.oauth.server.authserver.j2ee.GenericOAuthV2TokenServlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DummyTokenServlet extends GenericOAuthV2TokenServlet {

    private final AuthorizationServer authServer;
    private final DummyBackend backend;

    public DummyTokenServlet(final AuthorizationServer authServer, final DummyBackend backend) {
        this.authServer = authServer;
        this.backend = backend;
    }

    @Override
    protected void onBadTokenRequest(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        backend.onBadTokenRequest(error);
    }

    @Override
    protected void onInvalidClient(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        backend.onInvalidClient(error);
    }

    @Override
    protected void onServerError(final OAuthError error, final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        backend.onServerError(error);
    }

    @Override
    protected AuthorizationServer getAuthorizationServer() {
        return authServer;
    }

}
