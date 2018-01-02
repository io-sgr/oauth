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

package io.sgr.oauth.core.v20;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum AuthTokenErrorResponseType {

	// The request is missing a parameter so the server can’t proceed with the request.
	// This may also be returned if the request includes an unsupported parameter or repeats a parameter.
	@JsonProperty("invalid_request")
	INVALID_REQUEST,

	// Client authentication failed, such as if the request contains an invalid client ID or secret.
	// Send an HTTP 401 response in this case.
	@JsonProperty("invalid_client")
	INVALID_CLIENT,

	// The authorization code (or user’s password for the password grant type) is invalid or expired.
	// This is also the error you would return if the redirect URL given in the authorization grant does not match the URL provided in this access token request.
	@JsonProperty("invalid_grant")
	INVALID_GRANT,

	// For access token requests that include a scope (password or client_credentials grants), this error indicates an invalid scope value in the request.
	@JsonProperty("invalid_scope")
	INVALID_SCOPE,

	// This client is not authorized to use the requested grant type.
	// For example, if you restrict which applications can use the Implicit grant, you would return this error for the other apps.
	@JsonProperty("unauthorized_client")
	UNAUTHORIZED_CLIENT,

	// If a grant type is requested that the authorization server doesn't recognize, use this code.
	// Note that unknown grant types also use this specific error code rather than using the invalid_request above.
	@JsonProperty("unsupported_grant_type")
	UNSUPPORTED_GRANT_TYPE,
	;
}
