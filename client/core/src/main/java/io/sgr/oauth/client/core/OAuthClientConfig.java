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
package io.sgr.oauth.client.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import io.sgr.oauth.core.utils.JsonUtil;

/**
 * @author SgrAlpha
 *
 */
public class OAuthClientConfig implements Serializable {
	
	public final String clientId;
	public final String clientSecret;
	public final String authUri;
	public final String tokenUri;
	public final String revokeUri;
	
	/**
	 * @param clientId
	 * 				The client it
	 * @param clientSecret
	 * 				The client secret
	 * @param authUri
	 * 				The URI for OAuth authentication
	 * @param tokenUri
	 * 				The URI to get OAuth token
	 * @param revokeUri
	 * 				The URI to revoke a token
	 */
	@JsonCreator
	public OAuthClientConfig(
			@JsonProperty("client_id") String clientId,
			@JsonProperty("client_secret") String clientSecret,
			@JsonProperty("auth_uri") String authUri,
			@JsonProperty("token_uri") String tokenUri,
			@JsonProperty("revoke_uri") String revokeUri
			) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.authUri = authUri;
		this.tokenUri = tokenUri;
		this.revokeUri = revokeUri;
	}
	
	/**
	 * @param file
	 * 			The relative file name in class path to load GenericClientSecret from 
	 * @return
	 * 			The GenericClientSecret parsed from the specified file
	 * @throws IOException
	 * 			Failed to read from the specified file
	 */
	public static final OAuthClientConfig readFromClasspath(String file) throws IOException {
		try (
				InputStream in = OAuthClientConfig.class.getClassLoader().getResourceAsStream(file);
				) {
			return readFrom(in);
		} finally {
			
		}
	}
	
	/**
	 * @param in
	 * 			The input stream to read GenericClientSecret from
	 * @return
	 * 			The GenericClientSecret parsed from the specified file
	 * @throws IOException
	 * 			Failed to read from the specified file
	 */
	public static final OAuthClientConfig readFrom(InputStream in) throws IOException {
		return JsonUtil.getObjectMapper().readValue(in, OAuthClientConfig.class);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		try {
			return JsonUtil.getObjectMapper().writeValueAsString(this);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "";
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 7860561832133384705L;

}
