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
package io.sgr.oauth.client.core;

import java.io.Closeable;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

import io.sgr.oauth.client.core.exceptions.AccessTokenExpiredException;
import io.sgr.oauth.client.core.exceptions.InvalidAccessTokenException;
import io.sgr.oauth.client.core.exceptions.MissingAccessTokenException;
import io.sgr.oauth.client.core.exceptions.MissingAuthorizationCodeException;
import io.sgr.oauth.client.core.exceptions.MissingRefreshTokenException;
import io.sgr.oauth.client.core.exceptions.RefreshTokenRevokedException;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.OAuthException;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.ParameterStyle;
import io.sgr.oauth.core.v20.ResponseType;

/**
 * @author SgrAlpha
 *
 */
public interface OAuthHttpClient extends Closeable {
	
	/**
	 * @param responseType
	 * 				The type of the response, code, token or both
	 * @param redirectURL
	 * 				The redirect URL
	 * @param state
	 * 				The state
	 * @param scope
	 * 				The scope
	 * @param props
	 * 				Additional properties
	 * @return
	 * 				The generated URL
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	String getAuthorizeURL(ResponseType responseType, String redirectURL, String state, String scope, Map<String, String> props) throws OAuthException;
	
	/**
	 * @param style
	 * 				The style of the parameter, use query string or the body
	 * @param code
	 * 				The code used to get access token
	 * @param grantType
	 * 				The grant type, authorization code or refresh token, etc.
	 * @param redirectURL
	 * 				The redirect URL
	 * @return
	 * 				The OAuth credential, which contains access token, expiration time, and refresh token maybe
	 * @throws MissingAuthorizationCodeException
	 * 				If the authorization code is missing
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	OAuthCredential retrieveAccessToken(ParameterStyle style, String code, GrantType grantType, String redirectURL) throws OAuthException;
	
	/**
	 * @param style
	 * 				The style of the parameter, use query string or the body
	 * @param refreshToken
	 * 				The refresh token used to get a new access token
	 * @param grantType
	 * 				The grant type, authorization code or refresh token, etc.
	 * @return
	 * 				The OAuth credential, which contains access token, expiration time, and refresh token maybe
	 * @throws MissingRefreshTokenException
	 * 				If the refresh token is missing
	 * @throws RefreshTokenRevokedException
	 * 				If the refresh token has been revoked
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	OAuthCredential refreshToken(ParameterStyle style, String refreshToken, GrantType grantType) throws OAuthException;
	
	/**
	 * @param token
	 * 				The token to revoke, can be access token or refresh token.
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	void revokeToken(String token) throws OAuthException;
	
	/**
	 * @param credential
	 * 				The OAuth credential
	 * @param endpoint
	 * 				The end point of OAuth protected resource
	 * @param params
	 * 				The parameters needed to get OAuth protected resource
	 * @return
	 * 				A single resource
	 * @throws MissingAccessTokenException
	 * 				If the access token is missing
	 * @throws AccessTokenExpiredException
	 * 				If the access token is already expired
	 * @throws InvalidAccessTokenException
	 * 				If the access token is invalid
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	JsonNode getRawResource(OAuthCredential credential, String endpoint, String... params) throws MissingAccessTokenException, AccessTokenExpiredException, InvalidAccessTokenException, OAuthException;

	/**
	 * @param resultClass
	 * 				The class name of the result
	 * @param <T>
	 * 				The generic type of the result class
	 * @param credential
	 * 				The OAuth credential
	 * @param endpoint
	 * 				The end point of OAuth protected resource
	 * @param params
	 * 				The parameters needed to get OAuth protected resource
	 * @return
	 * 				A single resource
	 * @throws MissingAccessTokenException
	 * 				If the access token is missing
	 * @throws AccessTokenExpiredException
	 * 				If the access token is already expired
	 * @throws InvalidAccessTokenException
	 * 				If the access token is invalid
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	<T> T getResource(Class<T> resultClass, OAuthCredential credential, String endpoint, String... params) throws OAuthException;
	
	/**
	 * @param resultClass
	 * 				The class name of the result
	 * @param <T>
	 * 				The generic type of the result class
	 * @param treeKey
	 * 				The key to read a set of resources from
	 * @param credential
	 * 				The OAuth credential
	 * @param endpoint
	 * 				The end point of OAuth protected resource
	 * @param params
	 * 				The parameters needed to get OAuth protected resource
	 * @return
	 * 				A list of resources
	 * @throws MissingAccessTokenException
	 * 				If the access token is missing
	 * @throws AccessTokenExpiredException
	 * 				If the access token is already expired
	 * @throws InvalidAccessTokenException
	 * 				If the access token is invalid
	 * @throws OAuthException
	 * 				If anything goes wrong
	 */
	<T> List<T> getResources(Class<T> resultClass, String treeKey, OAuthCredential credential, String endpoint, String... params) throws OAuthException;
	
	/**
	 * @return
	 * 				OAuth client configuration
	 */
	OAuthClientConfig getOAuthClientConfig();

}
