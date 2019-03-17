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

package io.sgr.oauth.server.authserver.j2ee.utils;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;
import static io.sgr.oauth.server.authserver.j2ee.utils.OAuthV2WebConstants.DEFAULT_SCOPE_SPLITTER;

import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.v20.OAuth20;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

/**
 * @author SgrAlpha
 */
public class OAuthWebServerUtil {

    public static Optional<List<String>> parseScopes(final HttpServletRequest req) throws InvalidRequestException {
        return parseScopes(req, DEFAULT_SCOPE_SPLITTER);
    }

    public static Optional<List<String>> parseScopes(final HttpServletRequest req, final String splitter) throws InvalidRequestException {
        notNull(req, "Missing HttpServletRequest");
        notEmptyString(splitter, "Splitter needs to be specified");
        final String scopeNames = getOnlyOneParameter(req, OAuth20.OAUTH_SCOPE).orElse(null);
        final List<String> scopes;
        if (isEmptyString(scopeNames)) {
            scopes = null;
        } else {
            final String[] names = scopeNames.split(splitter);
            if (names.length == 0) {
                scopes = null;
            } else {
                scopes = Arrays.asList(names);
            }
        }
        return Optional.ofNullable(scopes);
    }

    public static Optional<String> getOnlyOneParameter(final HttpServletRequest req, final String parameter) throws InvalidRequestException {
        notNull(req, "Missing HttpServletRequest");
        notEmptyString(parameter, "Parameter name needs to be specified");
        if (req.getParameterValues(parameter) == null) {
            return Optional.empty();
        }
        if (req.getParameterValues(parameter).length > 1) {
            throw new InvalidRequestException(MessageFormat.format("Only one '{0}' parameter allowed", parameter));
        }
        final String value = req.getParameter(parameter);
        if (isEmptyString(value)) {
            return Optional.empty();
        }
        try {
            return Optional.of(URLDecoder.decode(value.trim(), "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

}
