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
package io.sgr.oauth.client.apachehttp;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import com.fasterxml.jackson.databind.JsonNode;
import io.sgr.oauth.client.core.OAuthClientConfig;
import io.sgr.oauth.client.core.OAuthHttpClient;
import io.sgr.oauth.client.core.exceptions.AccessTokenExpiredException;
import io.sgr.oauth.client.core.exceptions.InvalidAccessTokenException;
import io.sgr.oauth.client.core.exceptions.MissingAccessTokenException;
import io.sgr.oauth.client.core.exceptions.RefreshTokenRevokedException;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.OAuthException;
import io.sgr.oauth.core.exceptions.RecoverableOAuthException;
import io.sgr.oauth.core.exceptions.UnrecoverableOAuthException;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.OAuthError;
import io.sgr.oauth.core.v20.ParameterStyle;
import io.sgr.oauth.core.v20.ResponseType;
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.ProxySelector;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

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
		final RequestConfig reqConf = RequestConfig.custom()
				.setCookieSpec(CookieSpecs.DEFAULT)
				.setExpectContinueEnabled(true)
				.setTargetPreferredAuthSchemes(Arrays.asList(AuthSchemes.NTLM, AuthSchemes.DIGEST))
				.setProxyPreferredAuthSchemes(Collections.singletonList(AuthSchemes.BASIC))
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
		notNull(clientConfig, "OAuth client configuration should be provided.");
		JsonUtil.getObjectMapper().setDateFormat(dateFormat == null ? JsonUtil.getDefaultDateFormat() : dateFormat);
		try {
			return new OAuthApacheHttpClient(clientConfig);
		} catch (Throwable e) {
			throw new RuntimeException("Failed to init " + OAuthApacheHttpClient.class.getSimpleName(), e);
		}
	}
	
	@Override
	public String getAuthorizeURL(ResponseType responseType, String redirectURL, String state, String scope, Map<String, String> props) throws OAuthException {
		if (isEmptyString(redirectURL)) {
			throw new UnrecoverableOAuthException(new OAuthError("no_redirect_uri", "Can not get access token without redirect URI"));
		}
		final ResponseType oauthRespType = responseType == null ? ResponseType.CODE : responseType;
		final String oauthRespTypeStr = oauthRespType == ResponseType.CODE_AND_TOKEN ? ResponseType.CODE.name() + " " + ResponseType.TOKEN.name() : oauthRespType.name();
		try {
			final URIBuilder builder = new URIBuilder(this.clientConfig.authUri);
			builder.addParameter(OAuth20.OAUTH_RESPONSE_TYPE, oauthRespTypeStr.toLowerCase());
			builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
			builder.addParameter(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
			if (!isEmptyString(state)) {
				builder.addParameter(OAuth20.OAUTH_STATE, state);
			}
			if (!isEmptyString(scope)) {
				builder.addParameter(OAuth20.OAUTH_SCOPE, scope);
			}
			if (props != null && !props.isEmpty()) {
				for (Map.Entry<String, String> entry : props.entrySet()) {
					builder.addParameter(entry.getKey(), entry.getValue() == null ? "" : entry.getValue());
				}
			}
			return builder.build().toURL().toExternalForm();
		} catch (URISyntaxException | MalformedURLException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_auth_uri", String.format("Invalid auth URI: %s", this.clientConfig.authUri)));
		}
	}

	@Override
	public OAuthCredential retrieveAccessToken(ParameterStyle style, String code, GrantType grantType, String redirectURL) throws OAuthException {
		notEmptyString(code, "Missing authorization code");
		final GrantType oauthGrantType = grantType == null ? GrantType.AUTHORIZATION_CODE : grantType;
		final HttpRequestBase request;
		switch (style) {
			case QUERY_STRING:
				try {
					final URIBuilder builder = new URIBuilder(this.clientConfig.authUri);
					builder.addParameter(OAuth20.OAUTH_CODE, code);
					builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
					builder.addParameter(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
					builder.addParameter(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
					builder.addParameter(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase());
					request = new HttpGet(builder.build());
				} catch (URISyntaxException e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_token_uri", String.format("Invalid token URI: %s", this.clientConfig.tokenUri)));
				}
				break;
			default:
				try {
					final HttpPost post = new HttpPost(this.clientConfig.tokenUri);
					final List<NameValuePair> nameValuePairs = new ArrayList<>(5);
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CODE, code));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_REDIRECT_URI, redirectURL));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_GRANT_TYPE, oauthGrantType.name().toLowerCase()));
					post.setEntity(new UrlEncodedFormEntity(nameValuePairs));
					request = post;
				} catch (UnsupportedEncodingException e) {
					throw new UnrecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
				}
				break;
		}
		LOGGER.trace(request.getRequestLine().toString());
		try {
			final Future<HttpResponse> future = this.httpclient.execute(request, null);
			final HttpResponse resp = future.get();
			final StatusLine status = resp.getStatusLine();
			final HttpEntity entity = resp.getEntity();
			final String contentType = entity.getContentType().getValue();
			final String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() == 200) {
				try {
					return JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else {
				handlePossibleOAuthError(status, content);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		return null;
	}

	@Override
	public OAuthCredential getAccessTokenByAuthorizationCode(final String code, final String redirectURL) throws OAuthException {
		return getAccessTokenByAuthorizationCode(ParameterStyle.BODY, code, redirectURL);
	}

	@Override
	public OAuthCredential getAccessTokenByAuthorizationCode(final ParameterStyle style, final String code, final String redirectURL) throws OAuthException {
		notEmptyString(code, "Missing authorization code");
		final HttpRequestBase request;
		switch (style) {
			case QUERY_STRING:
				try {
					final URIBuilder builder = new URIBuilder(this.clientConfig.authUri);
					builder.addParameter(OAuth20.OAUTH_CODE, code);
					builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
					builder.addParameter(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
					builder.addParameter(OAuth20.OAUTH_REDIRECT_URI, redirectURL);
					builder.addParameter(OAuth20.OAUTH_GRANT_TYPE, GrantType.AUTHORIZATION_CODE.name().toLowerCase());
					request = new HttpGet(builder.build());
				} catch (URISyntaxException e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_token_uri", String.format("Invalid token URI: %s", this.clientConfig.tokenUri)));
				}
				break;
			default:
				try {
					final HttpPost post = new HttpPost(this.clientConfig.tokenUri);
					final List<NameValuePair> nameValuePairs = new ArrayList<>(5);
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CODE, code));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_REDIRECT_URI, redirectURL));
					nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_GRANT_TYPE, GrantType.AUTHORIZATION_CODE.name().toLowerCase()));
					post.setEntity(new UrlEncodedFormEntity(nameValuePairs));
					request = post;
				} catch (UnsupportedEncodingException e) {
					throw new UnrecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
				}
				break;
		}
		LOGGER.trace(request.getRequestLine().toString());
		try {
			final Future<HttpResponse> future = this.httpclient.execute(request, null);
			final HttpResponse resp = future.get();
			final StatusLine status = resp.getStatusLine();
			final HttpEntity entity = resp.getEntity();
			final String contentType = entity.getContentType().getValue();
			final String content = EntityUtils.toString(entity);

			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);

			if (status.getStatusCode() == 200) {
				try {
					return JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else {
				handlePossibleOAuthError(status, content);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		return null;
	}

	@Override
	public OAuthCredential getAccessTokenByUsernameAndPassword(final String username, final String password, final String redirectURL) throws OAuthException {
		notEmptyString(username, "Missing username");
		notEmptyString(password, "Missing password");
		final HttpRequestBase request;
		try {
			final HttpPost post = new HttpPost(this.clientConfig.tokenUri);
			final List<NameValuePair> nameValuePairs = new ArrayList<>(5);
			nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_USERNAME, username));
			nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_PASSWORD, password));
			nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId));
			nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret));
			nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_REDIRECT_URI, redirectURL));
			nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_GRANT_TYPE, GrantType.PASSWORD.name().toLowerCase()));
			post.setEntity(new UrlEncodedFormEntity(nameValuePairs));
			request = post;
		} catch (UnsupportedEncodingException e) {
			throw new UnrecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		LOGGER.trace(request.getRequestLine().toString());
		try {
			final Future<HttpResponse> future = this.httpclient.execute(request, null);
			final HttpResponse resp = future.get();
			final StatusLine status = resp.getStatusLine();
			final HttpEntity entity = resp.getEntity();
			final String contentType = entity.getContentType().getValue();
			final String content = EntityUtils.toString(entity);

			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);

			if (status.getStatusCode() == 200) {
				try {
					return JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else {
				handlePossibleOAuthError(status, content);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		return null;
	}

	@Override
	public OAuthCredential refreshToken(ParameterStyle style, String refreshToken) throws OAuthException {
		notEmptyString(refreshToken, "Missing refresh token");
		final HttpRequestBase request;
		try {
			switch (style) {
			case QUERY_STRING:
				final URIBuilder builder = new URIBuilder(this.clientConfig.tokenUri);
				builder.addParameter(OAuth20.OAUTH_REFRESH_TOKEN, refreshToken);
				builder.addParameter(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId);
				builder.addParameter(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret);
				builder.addParameter(OAuth20.OAUTH_GRANT_TYPE, GrantType.REFRESH_TOKEN.name().toLowerCase());
				request = new HttpGet(builder.build());
				break;
			default:
				final HttpPost post = new HttpPost(this.clientConfig.tokenUri);
				final List<NameValuePair> nameValuePairs = new ArrayList<>(4);
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_REFRESH_TOKEN, refreshToken));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_ID, this.clientConfig.clientId));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_CLIENT_SECRET, this.clientConfig.clientSecret));
				nameValuePairs.add(new BasicNameValuePair(OAuth20.OAUTH_GRANT_TYPE, GrantType.REFRESH_TOKEN.name().toLowerCase()));
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
			final Future<HttpResponse> future = this.httpclient.execute(request, null);
			final HttpResponse resp = future.get();
			final StatusLine status = resp.getStatusLine();
			final HttpEntity entity = resp.getEntity();
			final String contentType = entity.getContentType().getValue();
			final String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() == 200) {
				try {
					final OAuthCredential credential = JsonUtil.getObjectMapper().readValue(content, OAuthCredential.class);
					if (isEmptyString(credential.getRefreshToken())) {
						credential.setRefreshToken(refreshToken);
					}
					return credential;
				} catch (Exception e) {
					throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", content));
				}
			} else if (status.getStatusCode() == 401) {
				throw new RefreshTokenRevokedException();
			} else {
				handlePossibleOAuthError(status, content);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		return null;
	}

	@Override
	public void revokeToken(String token) throws OAuthException {
		notEmptyString(token, "Missing refresh token");
		final HttpRequestBase request;
		try {
			final URIBuilder builder = new URIBuilder(this.clientConfig.revokeUri);
			builder.addParameter(OAuth20.OAUTH_TOKEN, token);
			request = new HttpGet(builder.build());
			LOGGER.trace(request.getRequestLine().toString());
		} catch (URISyntaxException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_revoke_uri", String.format("Invalid revoke URI: %s", this.clientConfig.revokeUri)));
		}
		try {
			final Future<HttpResponse> future = this.httpclient.execute(request, null);
			final HttpResponse resp = future.get();
			final StatusLine status = resp.getStatusLine();
			final HttpEntity entity = resp.getEntity();
			final String contentType = entity.getContentType().getValue();
			final String content = EntityUtils.toString(entity);
			
			LOGGER.trace(resp.getStatusLine().toString());
			LOGGER.trace(contentType);
			LOGGER.trace(content);
			
			if (status.getStatusCode() != 200) {
				handlePossibleOAuthError(status, content);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
	}

	@Override
	public <T> T getResource(Class<T> resultClass, OAuthCredential credential, String endpoint, String... params) throws OAuthException {
		final JsonNode json = getRawResource(credential, endpoint, params);
		try {
			return JsonUtil.getObjectMapper().treeToValue(json, resultClass);
		} catch (IOException e) {
			throw new UnrecoverableOAuthException(new OAuthError("invalid_response_content", json.toString()));
		}
	}

	@Override
	public <T> List<T> getResources(Class<T> resultClass, String treeKey, OAuthCredential credential, String endpoint, String... params) throws OAuthException {
		JsonNode node = getRawResource(credential, endpoint, params);
		if (isEmptyString(treeKey)) {
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

	@Override
	public JsonNode getRawResource(OAuthCredential credential, String endpoint, String... params) throws UnrecoverableOAuthException, RecoverableOAuthException {
		if (credential == null || isEmptyString(credential.getAccessToken())) {
			throw new MissingAccessTokenException();
		}
		if (System.currentTimeMillis() > credential.getAccessTokenExpiration() * 1000) {
			throw new AccessTokenExpiredException();
		}
		final HttpRequestBase request;
		try {
			final URIBuilder builder = new URIBuilder(endpoint);
			if (params != null && params.length > 0) {
				String key, value;
				for (int p = 0; p + 1 < params.length; p += 2) {
					key = params[p];
					if (isEmptyString(key)) {
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
			final Future<HttpResponse> future = this.httpclient.execute(request, null);
			final HttpResponse resp = future.get();
			final StatusLine status = resp.getStatusLine();
			final HttpEntity entity = resp.getEntity();
			final String contentType = entity.getContentType().getValue();
			final String content = EntityUtils.toString(entity);
			
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
			} else {
				handlePossibleOAuthError(status, content);
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			throw new RecoverableOAuthException(new OAuthError(e.getMessage(), e.getMessage()));
		}
		return null;
	}

	private void handlePossibleOAuthError(final StatusLine status, final String content) throws UnrecoverableOAuthException, RecoverableOAuthException {
		if (status.getStatusCode() >= 400 && status.getStatusCode() < 500) {
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
	}

	@Override
	public OAuthClientConfig getOAuthClientConfig() {
		return this.clientConfig;
	}

	@Override
	public void close() throws IOException {
		this.httpclient.close();
	}

}
