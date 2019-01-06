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

package io.sgr.oauth.server.core.models;

import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuthClientInfo implements Serializable {

	private final String id;
	private String secret;
	private String name;
	private String description;
	private String iconUrl;
	private String privacyUrl;
	private final String owner;
	private final long createdTimeMs;
	private List<String> callbacks;

	public OAuthClientInfo(final String id, final String secret, final String name, final String description, final String iconUrl, final String privacyUrl, final String owner, final long createdTimeMs) {
		this(id, secret, name, description, iconUrl, privacyUrl, owner, createdTimeMs, null);
	}

	@JsonCreator
	public OAuthClientInfo(
			@JsonProperty("id") final String id,
			@JsonProperty("secret") final String secret,
			@JsonProperty("name") final String name,
			@JsonProperty("description") final String description,
			@JsonProperty("icon_url") final String iconUrl,
			@JsonProperty("privacy_url") final String privacyUrl,
			@JsonProperty("owner") final String owner,
			@JsonProperty("created_time") final long createdTimeMs,
			@JsonProperty("callbacks") final List<String> callbacks) {
		notEmptyString(id, "Client ID needs to be specified");
		this.id = id;
		setSecret(secret);
		setName(name);
		setDescription(description);
		setIconUrl(iconUrl);
		setPrivacyUrl(privacyUrl);
		notEmptyString(owner, "Owner UID needs to be specified");
		this.owner = owner;
		this.createdTimeMs = createdTimeMs;
		setCallbacks(callbacks);
	}

	@JsonProperty("id")
	public String getId() {
		return id;
	}

	@JsonProperty("secret")
	public String getSecret() {
		return secret;
	}

	public void setSecret(final String secret) {
		notEmptyString(secret, "Client secret needs to be specified");
		this.secret = secret;
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	public void setName(final String name) {
		notEmptyString(name, "Client name needs to be specified");
		this.name = name;
	}

	@JsonProperty("description")
	public Optional<String> getDescription() {
		return Optional.ofNullable(description);
	}

	public void setDescription(final String description) {
		this.description = Optional.ofNullable(description).orElse(null);
	}

	@JsonProperty("icon_url")
	public Optional<String> getIconUrl() {
		return Optional.ofNullable(iconUrl);
	}

	public void setIconUrl(final String iconUrl) {
		this.iconUrl = Optional.ofNullable(iconUrl).orElse(null);
	}

	@JsonProperty("privacy_url")
	public Optional<String> getPrivacyUrl() {
		return Optional.ofNullable(privacyUrl);
	}

	public void setPrivacyUrl(final String privacyUrl) {
		this.privacyUrl = Optional.ofNullable(privacyUrl).orElse(null);
	}

	@JsonProperty("owner")
	public String getOwner() {
		return owner;
	}

	@JsonProperty("created_time")
	public long getCreatedTimeMs() {
		return createdTimeMs;
	}

	@JsonProperty("callbacks")
	public List<String> getCallbacks() {
		return callbacks;
	}

	public void setCallbacks(final List<String> callbacks) {
		this.callbacks = Optional.ofNullable(callbacks).orElse(Collections.emptyList());
	}

	@Override public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof OAuthClientInfo)) {
			return false;
		}
		final OAuthClientInfo that = (OAuthClientInfo) o;
		return Objects.equals(getId(), that.getId());
	}

	@Override public int hashCode() {
		return Objects.hash(getId());
	}

}
