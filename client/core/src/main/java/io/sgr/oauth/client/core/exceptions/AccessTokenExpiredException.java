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

package io.sgr.oauth.client.core.exceptions;

import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;
import io.sgr.oauth.core.v20.OAuthError;

/**
 * @author SgrAlpha
 */
public class AccessTokenExpiredException extends UnrecoverableOAuthException {

    public AccessTokenExpiredException() {
        super(new OAuthError("access_token_expired", "The access token already expired."));
    }

    /**
     *
     */
    private static final long serialVersionUID = -6840095992772525895L;

}
