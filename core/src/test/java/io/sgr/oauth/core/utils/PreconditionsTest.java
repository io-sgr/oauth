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

package io.sgr.oauth.core.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

public class PreconditionsTest {

	@Test
	public void testBlankErrorMessage() {
		try {
			Preconditions.notNull(null, "");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(Preconditions.DEFAULT_ERROR_MESSAGE, e.getMessage());
		}
	}

	@Test
	public void testCheckNull() {
		try {
			Preconditions.notNull(null, "err msg");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("err msg", e.getMessage());
		}
		Preconditions.notNull("", "err?");
		Preconditions.notNull("\n", "err?");
		Preconditions.notNull("\n\n\n", "err?");
		Preconditions.notNull("abc", "err?");
	}

	@Test
	public void testCheckString() {
		assertTrue(Preconditions.isEmptyString(null));
		assertTrue(Preconditions.isEmptyString(""));
		assertTrue(Preconditions.isEmptyString("\n"));
		assertTrue(Preconditions.isEmptyString("\n\n\n"));
		assertTrue(Preconditions.isEmptyString(" "));
		assertTrue(Preconditions.isEmptyString(" \n"));
		assertFalse(Preconditions.isEmptyString("abd"));
		try {
			Preconditions.notEmptyString(null, "err msg");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("err msg", e.getMessage());
		}
		try {
			Preconditions.notEmptyString("", "err msg");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("err msg", e.getMessage());
		}
		try {
			Preconditions.notEmptyString("\n", "err msg");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("err msg", e.getMessage());
		}
		try {
			Preconditions.notEmptyString("\n\n\n", "err msg");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("err msg", e.getMessage());
		}
		Preconditions.notEmptyString("abd", "err?");
	}

}
