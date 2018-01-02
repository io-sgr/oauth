/*
 * Copyright 2018 SgrAlpha
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

package io.sgr.oauth.core.v20;

import static io.sgr.oauth.core.v20.AuthTokenErrorResponseType.INVALID_CLIENT;
import static io.sgr.oauth.core.v20.AuthTokenErrorResponseType.INVALID_GRANT;
import static io.sgr.oauth.core.v20.AuthTokenErrorResponseType.INVALID_REQUEST;
import static io.sgr.oauth.core.v20.AuthTokenErrorResponseType.INVALID_SCOPE;
import static io.sgr.oauth.core.v20.AuthTokenErrorResponseType.UNAUTHORIZED_CLIENT;
import static io.sgr.oauth.core.v20.AuthTokenErrorResponseType.UNSUPPORTED_GRANT_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.type.CollectionType;
import io.sgr.oauth.core.utils.JsonUtil;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

public class AuthTokenErrorResponseTypeTest {

	@Test
	public void testToJson() throws JsonProcessingException {
		final String json = JsonUtil.getObjectMapper().writeValueAsString(AuthTokenErrorResponseType.values());
		System.out.println(json);
		assertEquals("[\"invalid_request\",\"invalid_client\",\"invalid_grant\",\"invalid_scope\",\"unauthorized_client\",\"unsupported_grant_type\"]", json);
	}

	@Test
	public void testFromJson() throws IOException {
		final String json = "[\"invalid_request\",\"invalid_client\",\"invalid_grant\",\"invalid_scope\",\"unauthorized_client\",\"unsupported_grant_type\"]";
		final CollectionType type = JsonUtil.getObjectMapper().getTypeFactory().constructCollectionType(List.class, AuthTokenErrorResponseType.class);
		final List<AuthTokenErrorResponseType> types = JsonUtil.getObjectMapper().readValue(json, type);
		assertNotNull(types);
		assertEquals(6, types.size());
		assertEquals(INVALID_REQUEST, types.get(0));
		assertEquals(INVALID_CLIENT, types.get(1));
		assertEquals(INVALID_GRANT, types.get(2));
		assertEquals(INVALID_SCOPE, types.get(3));
		assertEquals(UNAUTHORIZED_CLIENT, types.get(4));
		assertEquals(UNSUPPORTED_GRANT_TYPE, types.get(5));
	}
}
