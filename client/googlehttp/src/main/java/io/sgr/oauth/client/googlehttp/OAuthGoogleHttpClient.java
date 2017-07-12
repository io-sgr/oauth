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
package io.sgr.oauth.client.googlehttp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.text.DateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.UrlEncodedContent;

import io.sgr.oauth.client.core.OAuthClientConfig;
import io.sgr.oauth.client.core.OAuthHttpClient;
import io.sgr.oauth.client.core.exceptions.AccessTokenExpiredException;
import io.sgr.oauth.client.core.exceptions.InvalidAccessTokenException;
import io.sgr.oauth.client.core.exceptions.MissingAccessTokenException;
import io.sgr.oauth.client.core.exceptions.MissingAuthorizationCodeException;
import io.sgr.oauth.client.core.exceptions.MissingRefreshTokenException;
import io.sgr.oauth.client.core.exceptions.RefreshTokenRevokedException;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.OAuthError;
import io.sgr.oauth.core.exceptions.OAuthException;
import io.sgr.oauth.core.exceptions.RecoverableOAuthException;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.utils.Preconditions;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.ParameterStyle;
import io.sgr.oauth.core.v20.ResponseType;

/**
 * @author SgrAlpha
 *
 */
public class OAuthGoogleHttpClient implements OAuthHttpClient {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuthGoogleHttpClient.class.getPackage().getName());
	
	private final OAuthClientConfig clientConfig;
	private final HttpRequestFactory reqFac;
	
	private OAuthGoogleHttpClient(final OAuthClientConfig clientConfig, final HttpTransport transport) {
		this.clientConfig = clientConfig;
		this.reqFac = transport.createRequestFactory(new OAuthHttpRequestInitializer());
	}
	
	/**
	 * @param clientConfig
	 * 				The OAuth client configuration
	 * @param transport
	 * 				The HttpTransport
	 * @param dateFormat
	 * 				The date format for JSON parser
	 * @return
	 * 				OAuth HTTP client
	 */
	public static OAuthHttpClient newInstance(final OAuthClientConfig clientConfig, final HttpTransport transport, final DateFormat dateFormat) {
		Preconditions.notNull(clientConfig, "OAuth client configuration should be provided.");
		JsonUtil.getObjectMapper().setDateFormat(dateFormat == null ? JsonUtil.getDefaultDateFormat() : dateFormat);
		try {
			return new OAuthGoogleHttpClient(clientConfig, transport);
		} catch (Throwable e) {
			throw new RuntimeException("Failed to init " + OAuthGoogleHttpClient.class.getSimpleName(), e);
		}
	}
	
	/* (non-Javadoc)
	 * @see org.isuper.oauth.http.OAuthHttpClient#getAuthorizeURL(org.isuper.oauth.v20.ResponseType, java.lang.String, java.lang.String, java.lang.String, java.util.Map)
	 */
	@Override
	public String getAuthorizeURL(ResponseType responseType, String redirectURL, String state, String scope, Map<String, String> props) throws OAuthException {
		if (Preconditions.isEmptyString(redirectURL)) {
			throw new UnrecoverableOAuthException(new OAuthError("no_redirect_uri", "Can not get access token without redirect URI"));
		}
		ResponseType oauthRespType = responseType == null ? ResponseType.CODE : responseType;
		try {
			GenericUrl url = new GenericUrl(this.clientConfig.authUri)
					.set(OAuth20.OAUTH_RESPONSE_TYPE, oauthRespType.name().toLowerCase())
					.set(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId)
					.set(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
			if (!Preconditions.isEmptyString(state)) {
				url.set(OAuth20.OAUTH_STATE, state);
			}
			if (!Preconditions.isEmptyString(scope)) {
				url.set(OAuth20.OAUTH_SCOPE, scope);
			}
			if (props != null && !props.isEmpty()) {
				for (Map.Entry<String, String> entry : props.entrySet()) {
					String key = entry.getKey();
					String value = entry.getValue();
					url.set(key, value == null ? "" : value);
				}
			}
			return url.build();
		} catch (IllegalArgumentException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_auth_uri", String.format("Invalid auth URI: %s", this.clientConfig.authUri)));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.http.OAuthHttpClient#retrieveAccessToken(org.isuper.oauth.v20.ParameterStyle, java.lang.String, org.isuper.oauth.v20.GrantType, java.lang.String)
	 */
	@Override
	public OAuthCredential retrieveAccessToken(ParameterStyle style, String code, GrantType grantType, String redirectURL) throws MissingAuthorizationCodeException, OAuthException {
		if (Preconditions.isEmptyString(code)) {
			throw new MissingAuthorizationCodeException();
		}
		GrantType oauthGrantType = grantType == null ? GrantType.AUTHORIZATION_CODE : grantType;
		HttpRequest request;
		try {
			switch (style) {
			case QUERY_STRING:
				GenericUrl url = new GenericUrl(this.clientConfig.tokenUri)
						.set(OAuth20.OAUTH_CODE, code)
						.set(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId)
						.set(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret)
						.set(OAuth20.OAUTH_REDIRECT_URI, redirectURL)
						.set(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
				request = this.reqFac.buildGetRequest(url);
				break;
			default:
				Map<String, String> paramsMap = new HashMap<>();
				paramsMap.put(OAuth20.OAUTH_CODE, code);
				paramsMap.put(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
				paramsMap.put(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
				paramsMap.put(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
				paramsMap.put(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
				request = this.reqFac.buildPostRequest(new GenericUrl(this.clientConfig.tokenUri), new UrlEncodedContent(paramsMap));
				break;
			}
		} catch (MalformedURLException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_token_uri", String.format("Invalid token URI: %s", this.clientConfig.tokenUri)));
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("failed_to_build_request", "Failed to build request"));
		}
		try {
			HttpResponse resp = request.execute();
			String content = resp.parseAsString();
			LOGGER.trace("Code: " + resp.getStatusCode());
			LOGGER.trace("Type: " + resp.getContentType());
			LOGGER.trace("Content: " + content);
			
			if (resp.isSuccessStatusCode()) {
				resp.disconnect();
				try {
					return JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (resp.getStatusCode() >= 400 && resp.getStatusCode() < 500) {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.client.OAuthHttpClient#refreshToken(org.isuper.oauth.v20.ParameterStyle, java.lang.String, org.isuper.oauth.v20.GrantType)
	 */
	@Override
	public OAuthCredential refreshToken(ParameterStyle style, String refreshToken, GrantType grantType) throws MissingRefreshTokenException, RefreshTokenRevokedException, OAuthException {
		if (Preconditions.isEmptyString(refreshToken)) {
			throw new MissingRefreshTokenException();
		}
		GrantType oauthGrantType = grantType == null ? GrantType.REFRESH_TOKEN : grantType;
		HttpRequest request;
		try {
			switch (style) {
			case QUERY_STRING:
				GenericUrl url = new GenericUrl(this.clientConfig.tokenUri)
										.set(OAuth20.OAUTH_REFRESH_TOKEN, refreshToken)
										.set(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId)
										.set(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret)
										.set(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
				request = this.reqFac.buildGetRequest(url);
				break;
			default:
				Map<String, String> paramsMap = new HashMap<>();
				paramsMap.put(OAuth20.OAUTH_REFRESH_TOKEN, refreshToken);
				paramsMap.put(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
				paramsMap.put(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
				paramsMap.put(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
				request = this.reqFac.buildPostRequest(new GenericUrl(this.clientConfig.tokenUri), new UrlEncodedContent(paramsMap));
				break;
			}
		} catch (MalformedURLException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_token_uri", String.format("Invalid token URI: %s", this.clientConfig.tokenUri)));
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("failed_to_build_request", "Failed to build request"));
		}
		try {
			HttpResponse resp = request.execute();
			String content = resp.parseAsString();
			LOGGER.trace("Code: " + resp.getStatusCode());
			LOGGER.trace("Type: " + resp.getContentType());
			LOGGER.trace("Content: " + content);
			
			if (resp.isSuccessStatusCode()) {
				resp.disconnect();
				try {
					OAuthCredential credential = JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
					if (Preconditions.isEmptyString(credential.getRefreshToken())) {
						credential.setRefreshToken(refreshToken);
					}
					return credential;
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (resp.getStatusCode() >= 400 && resp.getStatusCode() < 500) {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.client.core.OAuthHttpClient#revokeToken(java.lang.String)
	 */
	@Override
	public void revokeToken(String token) throws OAuthException {
		if (Preconditions.isEmptyString(token)) {
			throw new UnrecoverableOAuthException(new OAuthError("blank_tokne", "Need to specify a token to revoke"));
		}
		HttpRequest request;
		try {
			Map<String, String> paramsMap = new HashMap<>();
			paramsMap.put(OAuth20.OAUTH_TOKEN, token);
			GenericUrl url = new GenericUrl(this.clientConfig.revokeUri).set(OAuth20.OAUTH_TOKEN, token);
			request = this.reqFac.buildGetRequest(url);
		} catch (MalformedURLException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_revoke_uri", String.format("Invalid revoke URI: %s", this.clientConfig.revokeUri)));
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("failed_to_build_request", "Failed to build request"));
		}
		try {
			HttpResponse resp = request.execute();
			String content = resp.parseAsString();
			LOGGER.trace("Code: " + resp.getStatusCode());
			LOGGER.trace("Type: " + resp.getContentType());
			LOGGER.trace("Content: " + content);
			
			if (resp.isSuccessStatusCode()) {
				resp.disconnect();
			} else if (resp.getStatusCode() >= 400 && resp.getStatusCode() < 500) {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.http.OAuthHttpClient#getJSONResources(java.lang.Class, org.isuper.oauth.OAuthCredential, java.lang.String, java.lang.String[])
	 */
	@Override
	public <T> T getResource(Class<T> resultClass, OAuthCredential credential, String endpoint, String... params) throws MissingAccessTokenException, AccessTokenExpiredException, InvalidAccessTokenException, OAuthException {
		JsonNode node = getRawResource(credential, endpoint, params);
		try {
			return JsonUtil.getObjectMapper().treeToValue(node, resultClass);
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", node.toString()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.http.OAuthHttpClient#getResources(java.lang.Class, org.isuper.oauth.OAuthCredential, java.lang.String, java.lang.String[])
	 */
	@Override
	public <T> List<T> getResources(Class<T> resultClass, String treeKey, OAuthCredential credential, String endpoint, String... params) throws MissingAccessTokenException, AccessTokenExpiredException, InvalidAccessTokenException, OAuthException {
		JsonNode node = getRawResource(credential, endpoint, params);
		if (Preconditions.isEmptyString(treeKey)) {
			try {
				return JsonUtil.getObjectMapper().readValue(node.traverse(), JsonUtil.getObjectMapper().getTypeFactory().constructCollectionType(List.class, resultClass));
			} catch (IOException e) {
				throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", node.toString()));
			}
		}
		node = node.get(treeKey);
		try {
			return JsonUtil.getObjectMapper().readValue(node.traverse(), JsonUtil.getObjectMapper().getTypeFactory().constructCollectionType(List.class, resultClass));
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", node.toString()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.http.OAuthHttpClient#getRawResource(org.isuper.oauth.OAuthCredential, java.lang.String, java.lang.String[])
	 */
	@Override
	public JsonNode getRawResource(OAuthCredential credential, String endpoint, String... params) throws MissingAccessTokenException, AccessTokenExpiredException, InvalidAccessTokenException, OAuthException {
		if (credential == null || Preconditions.isEmptyString(credential.getAccessToken())) {
			throw new MissingAccessTokenException();
		}
		if (System.currentTimeMillis() > credential.getAccessTokenExpiration() * 1000) {
			throw new AccessTokenExpiredException();
		}
		HttpRequest req;
		try {
			GenericUrl url = new GenericUrl(endpoint).set(OAuth20.OAUTH_ACCESS_TOKEN, credential.getAccessToken());
			if (params != null && params.length > 0) {
				String key, value;
				for (int p = 0; p + 1 < params.length; p += 2) {
					key = params[p];
					if (Preconditions.isEmptyString(key)) {
						continue;
					}
					value = params[p + 1];
					url.set(key, value == null ? "" : value);
				}
			}
			req = this.reqFac.buildGetRequest(url);
		} catch (MalformedURLException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_endpoint", String.format("Invalid endpoint: %s", endpoint)));
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("failed_to_build_request", "Failed to build request"));
		}
		try {
			HttpResponse resp = req.execute();
			String content = resp.parseAsString();
			LOGGER.trace("Code: " + resp.getStatusCode());
			LOGGER.trace("Type: " + resp.getContentType());
			LOGGER.trace("Content: " + content);
			
			if (resp.isSuccessStatusCode()) {
				resp.disconnect();
				try {
					return JsonUtil.getObjectMapper().readTree(content);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (resp.getStatusCode() == 401) {
				resp.disconnect();
				throw new InvalidAccessTokenException();
			} else if (resp.getStatusCode() >= 400 && resp.getStatusCode() < 500) {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				resp.disconnect();
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + resp.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.client.OAuthHttpClient#getOAuthClientConfig()
	 */
	@Override
	public OAuthClientConfig getOAuthClientConfig() {
		return this.clientConfig;
	}

	/* (non-Javadoc)
	 * @see java.io.Closeable#close()
	 */
	@Override
	public void close() throws IOException {
		
	}

}
