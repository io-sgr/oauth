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

package io.sgr.oauth.server.core.exceptions;

import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;

public class BadOAuthRequestException extends UnrecoverableOAuthException {

	/**
	 * @param message The error message
	 */
	public BadOAuthRequestException(final String message) {
		this(new OAuthError("bad_oauth_request", message, null));
	}

	/**
	 * @param error The error
	 */
	public BadOAuthRequestException(final OAuthError error) {
		super(error);
	}
}