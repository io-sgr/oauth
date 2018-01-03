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

public enum OAuthErrorType {

	@JsonProperty("invalid_request")
	INVALID_REQUEST,

	@JsonProperty("invalid_scope")
	INVALID_SCOPE,

	@JsonProperty("unauthorized_client")
	UNAUTHORIZED_CLIENT,

	@JsonProperty("invalid_client")
	INVALID_CLIENT,

	@JsonProperty("unsupported_response_type")
	UNSUPPORTED_RESPONSE_TYPE,

	@JsonProperty("invalid_grant")
	INVALID_GRANT,

	@JsonProperty("unsupported_grant_type")
	UNSUPPORTED_GRANT_TYPE,

	@JsonProperty("access_denied")
	ACCESS_DENIED,

	@JsonProperty("server_error")
	SERVER_ERROR,

	@JsonProperty("temporarily_unavailable")
	TEMPORARILY_UNAVAILABLE,

	;
}
