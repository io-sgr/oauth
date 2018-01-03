/*
 * Copyright 2017 SgrAlpha
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

import static io.sgr.oauth.core.v20.AccessTokenErrorResponseType.INVALID_GRANT;

import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;

/**
 * @author SgrAlpha
 *
 */
public class MissingRefreshTokenException extends UnrecoverableOAuthException {

	public MissingRefreshTokenException() {
		super(new OAuthError(INVALID_GRANT.name().toLowerCase(), "The refresh token should be specified."));
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 6290573815101966462L;
	
}
