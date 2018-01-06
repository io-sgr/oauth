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

import java.io.Serializable;

public class ScopeDefinition implements Serializable {

	private final String id;
	private final String name;
	private final String description;

	public ScopeDefinition(final String id, final String name, final String description) {
		notEmptyString(id, "Scope ID needs to be specified");
		this.id = id;
		notEmptyString(name, "Scope name needs to be specified");
		this.name = name;
		notEmptyString(description, "Scope description needs to be specified");
		this.description = description;
	}

	public String getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}
}
