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

package io.sgr.oauth.core.exceptions;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;

import io.sgr.oauth.core.v20.OAuthErrorType;
import org.junit.Test;

import java.text.MessageFormat;

public class AccessDeniedExceptionTest {

	@Test(expected = AccessDeniedException.class)
	public void testBasicMethods() throws AccessDeniedException {
		final String errorDescription = "Somehow access denied";
		final AccessDeniedException e = new AccessDeniedException(errorDescription);
		assertNotNull(e.getError());
		assertEquals(MessageFormat.format("{0}: {1}", OAuthErrorType.ACCESS_DENIED.name().toLowerCase(), errorDescription), e.getMessage());
		assertEquals(OAuthErrorType.ACCESS_DENIED.name().toLowerCase(), e.getError().getName());
		assertEquals(errorDescription, e.getError().getErrorDescription());
		throw e;
	}
}
