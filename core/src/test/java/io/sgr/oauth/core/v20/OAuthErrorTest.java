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

package io.sgr.oauth.core.v20;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.junit.Test;

public class OAuthErrorTest {

	@Test
	public void testConstructor() {
		OAuthError err;

		final String error = OAuthErrorType.INVALID_GRANT.name().toLowerCase();
		final String errorDescription = "This is a description";
		err = new OAuthError(error, errorDescription);
		assertEquals(error, err.getName());
		assertEquals(errorDescription, err.getErrorDescription());
		assertNull(err.getErrorUri());

		final String errorUri = "http://localhost/api/how-to.html";
		err = new OAuthError(error, errorDescription, errorUri);
		assertEquals(error, err.getName());
		assertEquals(errorDescription, err.getErrorDescription());
		assertEquals(errorUri, err.getErrorUri());
	}

	@Test
	public void testConstructorWithInvalidArguments() {
		try {
			new OAuthError(null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new OAuthError("\n", null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
	}
}
