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
package io.sgr.oauth.core.exceptions;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author SgrAlpha
 *
 */
public class OAuthError {

	private final String name;
	private final String description;

	/**
	 * @param error
	 * 					The name of the error
	 * @param description
	 * 					The description of the error
	 */
	@JsonCreator
	public OAuthError(@JsonProperty("error") String error, @JsonProperty("error_description") String description) {
		this.name = error;
		this.description = description;
	}

	/**
	 * @return the name
	 * 					The name of the error
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * @return the description
	 * 					The description of the error
	 */
	public String getDescription() {
		return this.description;
	}

}
