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
package io.sgr.oauth.client.apachehttp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.ProxySelector;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;

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
public class OAuthApacheHttpClient implements OAuthHttpClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(OAuthApacheHttpClient.class.getPackage().getName());
	
	private final OAuthClientConfig clientConfig;
	private final CloseableHttpAsyncClient httpclient;
	
	private OAuthApacheHttpClient(final OAuthClientConfig clientConfig) {
		this.clientConfig = clientConfig;
		RequestConfig reqConf = RequestConfig.custom()
				.setCookieSpec(CookieSpecs.DEFAULT)
				.setExpectContinueEnabled(true)
				.setTargetPreferredAuthSchemes(Arrays.asList(AuthSchemes.NTLM, AuthSchemes.DIGEST))
				.setProxyPreferredAuthSchemes(Arrays.asList(AuthSchemes.BASIC))
				.build();
		this.httpclient = HttpAsyncClients.custom()
				.useSystemProperties()
				.setDefaultCookieStore(new BasicCookieStore())
				.setDefaultRequestConfig(reqConf)
				.setRoutePlanner(new SystemDefaultRoutePlanner(ProxySelector.getDefault()))
				.build();
		this.httpclient.start();
	}
	
	/**
	 * @param clientConfig
	 * 				The OAuth client configuration
	 * @param dateFormat
	 * 				The date format for JSON parser
	 * @return
	 * 				OAuth HTTP client
	 */
	public static OAuthHttpClient newInstance(final OAuthClientConfig clientConfig, final DateFormat dateFormat) {
		Preconditions.notNull(clientConfig, "OAuth client configuration should be provided.");
		JsonUtil.getObjectMapper().setDateFormat(dateFormat == null ? JsonUtil.getDefaultDateFormat() : dateFormat);
		try {
			return new OAuthApacheHttpClient(clientConfig);
		} catch (Throwable e) {
			throw new RuntimeException("Failed to init " + OAuthApacheHttpClient.class.getSimpleName(), e);
		}
	}
	
	/* (non-Javadoc)
	 * @see org.isuper.oauth.client.OAuthHttpClient#getAuthorizeURL(org.isuper.oauth.v20.ResponseType, java.lang.String, java.lang.String, java.lang.String, java.util.Map)
	 */
	@Override
	public String getAuthorizeURL(ResponseType responseType, String redirectURL, String state, String scope, Map<String, String> props) throws OAuthException {
		if (Preconditions.isEmptyString(redirectURL)) {
			throw new UnrecoverableOAuthException(new OAuthError("no_redirect_uri", "Can not get access token without redirect URI"));
		}
		ResponseType oauthRespType = responseType == null ? ResponseType.CODE : responseType;
		try {
			URIBuilder builder = new URIBuilder(this.clientConfig.authUri);
			builder.addParameter(OAuth20.OAUTH_RESPONSE_TYPE, oauthRespType.name().toLowerCase());
			builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
			builder.addParameter(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
			if (!Preconditions.isEmptyString(state)) {
				builder.addParameter(OAuth20.OAUTH_STATE, state);
			}
			if (!Preconditions.isEmptyString(scope)) {
				builder.addParameter(OAuth20.OAUTH_SCOPE, scope);
			}
			if (props != null && !props.isEmpty()) {
				for (Map.Entry<String, String> entry : props.entrySet()) {
					String key = entry.getKey();
					String value = entry.getValue();
					builder.addParameter(key, value == null ? "" : value);
				}
			}
			return builder.build().toURL().toExternalForm();
		} catch (URISyntaxException | MalformedURLException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_auth_uri", String.format("Invalid auth URI: %s", this.clientConfig.authUri)));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.client.OAuthHttpClient#retrieveAccessToken(org.isuper.oauth.v20.ParameterStyle, java.lang.String, org.isuper.oauth.v20.GrantType, java.lang.String)
	 */
	@Override
	public OAuthCredential retrieveAccessToken(ParameterStyle style, String code, GrantType grantType, String redirectURL) throws MissingAuthorizationCodeException, OAuthException {
		if (Preconditions.isEmptyString(code)) {
			throw new MissingAuthorizationCodeException();
		}
		GrantType oauthGrantType = grantType == null ? GrantType.AUTHORIZATION_CODE : grantType;
		HttpRequestBase request;
		try {
			switch (style) {
			case QUERY_STRING:
				URIBuilder builder = new URIBuilder(this.clientConfig.authUri);
				builder.addParameter(OAuth20.OAUTH_CODE, code);
				builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
				builder.addParameter(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
				builder.addParameter(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
				builder.addParameter(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
				request = new HttpGet(builder.build());
				break;
			default:
				HttpPost post = new HttpPost(this.clientConfig.tokenUri);
				List<NameValuePair> nameValuePairs = new ArrayList<>(5);
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CODE, code));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_REDIRECT_URI, redirectURL));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase()));
				post.setEntity(new UrlEncodedFormEntity(nameValuePairs));
				request = post;
				break;
			}
			LOGGER.trace(request.getRequestLine().toString());
		} catch (URISyntaxException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_token_uri", String.format("Invalid token URI: %s", this.clientConfig.tokenUri)));
		} catch (UnsupportedEncodingException e) {
			throw new UnrecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		try {
			Future<HttpResponse> future = this.httpclient.execute(request, null);
			HttpResponse resp = future.get();
			StatusLine status = resp.getStatusLine();
			HttpEntity entity = resp.getEntity();
			String contentType = entity.getContentType().getValue();
			String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() == 200) {
				try {
					return JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (status.getStatusCode() >= 400 && status.getStatusCode() < 500) {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (IOException e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
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
		HttpRequestBase request;
		try {
			switch (style) {
			case QUERY_STRING:
				URIBuilder builder = new URIBuilder(this.clientConfig.tokenUri);
				builder.addParameter(OAuth20.OAUTH_REFRESH_TOKEN, refreshToken);
				builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
				builder.addParameter(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
				builder.addParameter(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
				request = new HttpGet(builder.build());
				break;
			default:
				HttpPost post = new HttpPost(this.clientConfig.tokenUri);
				List<NameValuePair> nameValuePairs = new ArrayList<>(4);
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_REFRESH_TOKEN, refreshToken));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase()));
				post.setEntity(new UrlEncodedFormEntity(nameValuePairs));
				request = post;
				break;
			}
			LOGGER.trace(request.getRequestLine().toString());
		} catch (URISyntaxException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_token_uri", String.format("Invalid token URI: %s", this.clientConfig.tokenUri)));
		} catch (UnsupportedEncodingException e) {
			throw new UnrecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		try {
			Future<HttpResponse> future = this.httpclient.execute(request, null);
			HttpResponse resp = future.get();
			StatusLine status = resp.getStatusLine();
			HttpEntity entity = resp.getEntity();
			String contentType = entity.getContentType().getValue();
			String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() == 200) {
				try {
					OAuthCredential credential = JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
					if (Preconditions.isEmptyString(credential.getRefreshToken())) {
						credential.setRefreshToken(refreshToken);
					}
					return credential;
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (status.getStatusCode() == 401) {
				throw new RefreshTokenRevokedException();
			} else if (status.getStatusCode() >= 400 && status.getStatusCode() < 500) {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (IOException e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
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
		HttpRequestBase request;
		try {
			URIBuilder builder = new URIBuilder(this.clientConfig.revokeUri);
			builder.addParameter(OAuth20.OAUTH_TOKEN, token);
			request = new HttpGet(builder.build());
			LOGGER.trace(request.getRequestLine().toString());
		} catch (URISyntaxException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_revoke_uri", String.format("Invalid revoke URI: %s", this.clientConfig.revokeUri)));
		}
		try {
			Future<HttpResponse> future = this.httpclient.execute(request, null);
			HttpResponse resp = future.get();
			StatusLine status = resp.getStatusLine();
			HttpEntity entity = resp.getEntity();
			String contentType = entity.getContentType().getValue();
			String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() == 200) {
				//
			} else if (status.getStatusCode() >= 400 && status.getStatusCode() < 500) {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
	}

	/* (non-Javadoc)
	 * @see org.isuper.oauth.http.OAuthHttpClient#getJSONResources(java.lang.Class, org.isuper.oauth.OAuthCredential, java.lang.String, java.lang.String[])
	 */
	@Override
	public <T> T getResource(Class<T> resultClass, OAuthCredential credential, String endpoint, String... params) throws MissingAccessTokenException, AccessTokenExpiredException, InvalidAccessTokenException, OAuthException {
		JsonNode json = getRawResource(credential, endpoint, params);
		try {
			return JsonUtil.getObjectMapper().treeToValue(json, resultClass);
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", json.toString()));
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
	 * @see org.isuper.oauth.client.OAuthHttpClient#getRawResource(org.isuper.oauth.OAuthCredential, java.lang.String, java.lang.String[])
	 */
	@Override
	public JsonNode getRawResource(OAuthCredential credential, String endpoint, String... params) throws MissingAccessTokenException, AccessTokenExpiredException, InvalidAccessTokenException, OAuthException {
		if (credential == null || Preconditions.isEmptyString(credential.getAccessToken())) {
			throw new MissingAccessTokenException();
		}
		if (System.currentTimeMillis() > credential.getAccessTokenExpiration() * 1000) {
			throw new AccessTokenExpiredException();
		}
		HttpRequestBase request;
		try {
			URIBuilder builder = new URIBuilder(endpoint);
			if (params != null && params.length > 0) {
				String key, value;
				for (int p = 0; p + 1 < params.length; p += 2) {
					key = params[p];
					if (Preconditions.isEmptyString(key)) {
						continue;
					}
					value = params[p + 1];
					builder.addParameter(key, value == null ? "" : value);
				}
			}
			request = new HttpGet(builder.build());
			request.addHeader("Authorization", credential.getTokenType() + " " + credential.getAccessToken());
			
			LOGGER.trace(request.getRequestLine().toString());
		} catch (URISyntaxException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_endpoint", String.format("Invalid endpoint: %s", endpoint)));
		}
		try {
			Future<HttpResponse> future = this.httpclient.execute(request, null);
			HttpResponse resp = future.get();
			StatusLine status = resp.getStatusLine();
			HttpEntity entity = resp.getEntity();
			String contentType = entity.getContentType().getValue();
			String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() == 200) {
				try {
					return JsonUtil.getObjectMapper().readTree(content);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (status.getStatusCode() == 401) {
				throw new InvalidAccessTokenException();
			} else if (status.getStatusCode() >= 400 && status.getStatusCode() < 500) {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new UnrecoverableOAuthException(error);
			} else {
				OAuthError error;
				try {
					error = JsonUtil.getObjectMapper().readValue(content, OAuthError.class);
				} catch (Exception e) {
					error = new OAuthError("" + status.getStatusCode(), content);
				}
				throw new RecoverableOAuthException(error);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
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
		this.httpclient.close();
	}

}
