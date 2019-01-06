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

package io.sgr.oauth.server.authserver.core;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.sgr.oauth.core.utils.JsonUtil;

import java.io.IOException;
import java.text.MessageFormat;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.Optional;

public class JwtAuthorizationCodec implements AuthorizationCodec<AuthorizationDetail> {

	private static final long DEFAULT_EXPIRES_TIME_AMOUNT = 1L;
	private static final TemporalUnit DEFAULT_EXPIRES_TIME_UNIT = ChronoUnit.MINUTES;
	private static final ObjectMapper OBJECT_MAPPER = JsonUtil.getObjectMapper();

	static {
		OBJECT_MAPPER.registerModule(new Jdk8Module());
	}

	private final String issuer;
	private final String secret;

	private Long expiresTimeAmount;
	private TemporalUnit expiresTimeUnit;

	public JwtAuthorizationCodec(final String issuer, final String secret) {
		notEmptyString(issuer, "Missing issuer");
		this.issuer = issuer;
		notEmptyString(secret, "Missing secret");
		this.secret = secret;
	}

	@Override public String encode(final AuthorizationDetail authDetail) throws JwtException {
		notNull(authDetail, "Missing authorization detail");
		final Instant now = Instant.now(Clock.systemUTC());
		final Instant expiration = now.plus(
				Optional.ofNullable(expiresTimeAmount).orElse(DEFAULT_EXPIRES_TIME_AMOUNT),
				Optional.ofNullable(expiresTimeUnit).orElse(DEFAULT_EXPIRES_TIME_UNIT)
		);
		final String subject;
		try {
			subject = OBJECT_MAPPER.writeValueAsString(authDetail);
		} catch (JsonProcessingException e) {
			throw new JwtException("Unable to serialize subject", e);
		}
		return Jwts.builder()
				.setIssuer(issuer)
				.setSubject(subject)
				.setIssuedAt(Date.from(now))
				.setExpiration(Date.from(expiration))
				.signWith(SignatureAlgorithm.HS512, secret)
				.compact();
	}

	@Override public AuthorizationDetail decode(final String authCode) throws JwtException {
		notEmptyString(authCode, "Missing authorization code");
		final Claims body = Jwts.parser()
				.requireIssuer(issuer)
				.setSigningKey(secret)
				.parseClaimsJws(authCode).getBody();
		final String subject = body.getSubject();
		if (isEmptyString(subject)) {
			throw new MalformedJwtException("Missing subject in the token");
		}
		try {
			return OBJECT_MAPPER.readValue(subject, AuthorizationDetail.class);
		} catch (IOException e) {
			throw new MalformedJwtException(MessageFormat.format("Invalid subject: {0}", subject));
		}
	}

	public JwtAuthorizationCodec setExpiresIn(final long amount, final TemporalUnit unit) {
		if (amount <= 0) {
			throw new IllegalArgumentException(MessageFormat.format("Time amount should be greater than 0, but got {0}", amount));
		}
		this.expiresTimeAmount = amount;
		notNull(unit, "Time unit needs to be specified");
		this.expiresTimeUnit = unit;
		return this;
	}

}
