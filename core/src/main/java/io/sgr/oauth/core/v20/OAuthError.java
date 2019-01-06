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
package io.sgr.oauth.core.v20;

import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author SgrAlpha
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuthError {

	private final String name;
	private final String errorDescription;
	private final String errorUri;

	/**
	 * @param error            The error
	 * @param errorDescription Optional. The error description. Can only include ASCII characters, and should be a
	 *                         sentence or two at most describing the circumstance of the error.
	 */
	public OAuthError(final String error, final String errorDescription) {
		this(error, errorDescription, null);
	}

	/**
	 * @param error            The error
	 * @param errorDescription Optional. The error description. Can only include ASCII characters, and should be a
	 *                         sentence or two at most describing the circumstance of the error.
	 * @param errorUri         Optional. The link to API documentation for information about how to correct the
	 *                         specific error that was encountered.
	 */
	@JsonCreator
	public OAuthError(
			@JsonProperty("error") final String error,
			@JsonProperty("error_description") final String errorDescription,
			@JsonProperty("error_uri") final String errorUri) {
		notEmptyString(error, "Error should be specified");
		this.name = error;
		this.errorDescription = errorDescription;
		this.errorUri = errorUri;
	}

	/**
	 * @return The error
	 */
	@JsonProperty("error")
	public String getName() {
		return this.name;
	}

	/**
	 * @return The error description
	 */
	@JsonProperty("error_description")
	public String getErrorDescription() {
		return this.errorDescription;
	}

	/**
	 * @return The link to API doc for info
	 */
	@JsonProperty("error_uri")
	public String getErrorUri() {
		return errorUri;
	}
}
