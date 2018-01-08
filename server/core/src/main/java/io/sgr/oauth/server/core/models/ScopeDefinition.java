/*
 * Copyright 2017-2018 SgrAlpha
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

package io.sgr.oauth.server.core.models;

import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScopeDefinition implements Serializable {

	private final String id;
	private final String name;
	private final String description;

	@JsonCreator
	public ScopeDefinition(
			@JsonProperty("id") final String id,
			@JsonProperty("name") final String name,
			@JsonProperty("description") final String description) {
		notEmptyString(id, "Scope ID needs to be specified");
		this.id = id;
		notEmptyString(name, "Scope name needs to be specified");
		this.name = name;
		notEmptyString(description, "Scope description needs to be specified");
		this.description = description;
	}

	@JsonProperty("id")
	public String getId() {
		return id;
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("description")
	public String getDescription() {
		return description;
	}

	@Override public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof ScopeDefinition)) {
			return false;
		}
		final ScopeDefinition that = (ScopeDefinition) o;
		return Objects.equals(getId(), that.getId());
	}

	@Override public int hashCode() {
		return Objects.hash(getId());
	}

}
