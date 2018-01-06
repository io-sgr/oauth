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
package io.sgr.oauth.core;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.v20.OAuth20;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author SgrAlpha
 *
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuthCredential implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6434693647236278615L;

	public static final String DEFAULT_TOKEN_TYPE = "Bearer";

	public static long DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC = TimeUnit.HOURS.toSeconds(1);

	private final String accessToken;
	private final String tokenType;
	private Long accessTokenExpiration;
	private String refreshToken;
	private Map<String, Object> extraParams;

	/**
	 * @param accessToken
	 * 				The access_token
	 * @param tokenType
	 * 				The token_type
	 */
	public OAuthCredential(String accessToken, String tokenType) {
		this.accessToken = accessToken;
		if (this.accessToken != null && this.accessToken.trim().length() > 0) {
			this.tokenType = tokenType == null || tokenType.trim().length() <= 0 ? DEFAULT_TOKEN_TYPE : tokenType;
		} else {
			this.tokenType = null;
		}
	}
	
	/**
	 * @param accessToken
	 * 				The access_token
	 * @param tokenType
	 * 				The token_type
	 * @param expiresIn
	 * 				The expires_in
	 * @param refreshToken
	 * 				The refresh_token
	 */
	@JsonCreator
	public OAuthCredential(
			@JsonProperty(OAuth20.OAUTH_ACCESS_TOKEN) String accessToken,
			@JsonProperty(OAuth20.OAUTH_TOKEN_TYPE) String tokenType,
			@JsonProperty(OAuth20.OAUTH_EXPIRES_IN) Integer expiresIn,
			@JsonProperty(OAuth20.OAUTH_REFRESH_TOKEN) String refreshToken
			) {
		this.accessToken = accessToken;
		if (this.accessToken != null && this.accessToken.trim().length() > 0) {
			this.tokenType = tokenType == null || tokenType.trim().length() <= 0 ? DEFAULT_TOKEN_TYPE : tokenType;
		} else {
			this.tokenType = null;
		}
		this.setAccessTokenExpiresIn(expiresIn);
		this.setRefreshToken(refreshToken);
	}
	
	/**
	 * @return 
	 * 				The access token
	 */
	@JsonProperty(OAuth20.OAUTH_ACCESS_TOKEN)
	public String getAccessToken() {
		return this.accessToken;
	}

	/**
	 * @return
	 * 				The tokenType
	 */
	@JsonProperty(OAuth20.OAUTH_TOKEN_TYPE)
	public String getTokenType() {
		return this.tokenType;
	}

	/**
	 * @param accessTokenExpiration
	 * 				The accessTokenExpiration to set
	 */
	public void setAccessTokenExpiration(Long accessTokenExpiration) {
		this.accessTokenExpiration = accessTokenExpiration;
	}

	/**
	 * @return 
	 * 				The access token expiration in second
	 */
	@JsonIgnore
	public Long getAccessTokenExpiration() {
		return this.accessTokenExpiration;
	}

	/**
	 * @param accessTokenExpiresIn
	 * 				The accessTokenExpiresIn to set
	 */
	public void setAccessTokenExpiresIn(Integer accessTokenExpiresIn) {
		if (this.accessToken != null && this.accessToken.trim().length() > 0) {
			this.setAccessTokenExpiration(System.currentTimeMillis() + (accessTokenExpiresIn == null || accessTokenExpiresIn <= 0 ? DEFAULT_ACCESS_TOKEN_EXPIRES_IN_SEC : accessTokenExpiresIn) * 1000);
		} else {
			this.setAccessTokenExpiration(null);
		}
	}

	/**
	 * @return
	 * 				The access token expires in second
	 */
	@JsonProperty(OAuth20.OAUTH_EXPIRES_IN)
	public Integer getAccessTokenExpiresIn() {
		if (this.getAccessTokenExpiration() == null) {
			return null;
		}
		return (int) ((this.getAccessTokenExpiration() - System.currentTimeMillis()) / 1000);
	}

	/**
	 * @return
	 * 				The refresh token
	 */
	@JsonProperty(OAuth20.OAUTH_REFRESH_TOKEN)
	public String getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * @param refreshToken
	 * 				The refreshToken to set
	 */
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	/**
	 * @return
	 * 				The extraParams
	 */
	@JsonAnyGetter
	public Map<String, Object> getExtraParams() {
		return this.extraParams;
	}

	/**
	 * @param extraParams
	 * 				The extraParams to set
	 */
	public void setExtraParams(Map<String, Object> extraParams) {
		this.extraParams = extraParams;
	}
	
	/**
	 * @param key
	 * 				The key of extra parameter to add
	 * @param value
	 * 				The value of extra parameter to add
	 */
	@JsonAnySetter
	public void addExtraParams(String key, Object value) {
		if (this.extraParams == null) {
			this.extraParams = new HashMap<>();
		}
		this.extraParams.put(key, value);
	}
	
	public String toJSON() {
		try {
			return JsonUtil.getObjectMapper().writeValueAsString(this);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "{}";
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return this.toJSON();
	}

}
