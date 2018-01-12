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

package io.sgr.oauth.server.core.models;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class ScopeDefinitionTest {

	@Test
	public void testEqual() {
		final ScopeDefinition def1 = new ScopeDefinition("basic", "Basic", "The basic scope");
		assertNotEquals(null, def1);
		assertNotEquals(new Object(), def1);
		assertEquals(def1, def1);
		assertFalse(def1.equals(new Object()));

		final ScopeDefinition def2 = new ScopeDefinition("basic", "Basic2", "The basic scope2");
		assertEquals(def1, def2);

		final Set<ScopeDefinition> all = new HashSet<>();
		all.add(def1);
		all.add(def2);
		assertEquals(1, all.size());
	}

	@Test
	public void testCreateScopeDefinition() {
		final ScopeDefinition def = new ScopeDefinition("basic", "Basic", "The basic scope");
		assertEquals("basic", def.getId());
		assertEquals("Basic", def.getName());
		assertEquals("The basic scope", def.getDescription());
	}

	@Test
	public void testCreateWithInvalidArguments() {
		try {
			new ScopeDefinition(null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("", null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("\n", null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("basic", null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("basic", "", null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("basic", "\n", null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("basic", "Basic", null);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("basic", "Basic", "");
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
		try {
			new ScopeDefinition("basic", "Basic", "\n");
			fail();
		} catch (IllegalArgumentException e) {
			// Ignored
		}
	}
}
