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

package io.sgr.oauth.server.core.models;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.time.Clock;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class OAuthClientInfoTest {

	@Test
	public void testCreateWithInvalidArguments() {
		final String name = "example";
		final long now = Clock.systemUTC().millis();
//		try {
//			new OAuthClientInfo(null, null, null, null, null, null);
//			fail();
//		} catch (IllegalArgumentException e) {
//			// Ignore
//		}
//		try {
//			new OAuthClientInfo(name, null, null, null, null, null);
//			fail();
//		} catch (IllegalArgumentException e) {
//			// Ignore
//		}
		try {
			new OAuthClientInfo(null, null, null, null, null, null, null, now);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			new OAuthClientInfo(UUID.randomUUID().toString(), null, null, null, null, null, null, now);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			new OAuthClientInfo(UUID.randomUUID().toString(), UUID.randomUUID().toString(), null, null, null, null, null, now);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
		try {
			new OAuthClientInfo(UUID.randomUUID().toString(), UUID.randomUUID().toString(), name, null, null, null, null, now);
			fail();
		} catch (IllegalArgumentException e) {
			// Ignore
		}
	}

	@Test
	public void testCreateWithValidArguments() {
		final String name = "example";
		final String desc = "This is a simple description";
		final String iconUrl = "https://localhost/images/app.png";
		final String privacyUrl = "https://localhost/privacy.html";
		final List<String> callbacks = Collections.singletonList("https://localhost/callback");
		final String ownerUid = "example_uid";
		final long now = Clock.systemUTC().millis();
		try {
			OAuthClientInfo info;
//			info = new OAuthClientInfo(name, null, null, null, ownerUid, null);
//			assertNotNull(info.getId());
//			assertNotNull(info.getSecret());
//			assertEquals(name, info.getName());
//			assertFalse(info.getDescription().isPresent());
//			assertFalse(info.getIconUrl().isPresent());
//			assertFalse(info.getPrivacyUrl().isPresent());
//			assertNotNull(info.getCallbacks());
//			assertEquals(0, info.getCallbacks().size());
//			assertEquals(ownerUid, info.getOwnerUid());
//			assertTrue(info.getCreatedTimeMs() > 0);
//
			info = new OAuthClientInfo(UUID.randomUUID().toString(), UUID.randomUUID().toString(), name, null, null, null, ownerUid, now, null);
			assertNotNull(info.getId());
			assertNotNull(info.getSecret());
			assertEquals(name, info.getName());
			assertFalse(info.getDescription().isPresent());
			assertFalse(info.getIconUrl().isPresent());
			assertFalse(info.getPrivacyUrl().isPresent());
			assertNotNull(info.getCallbacks());
			assertEquals(0, info.getCallbacks().size());
			assertEquals(ownerUid, info.getOwnerUid());
			assertEquals(now, info.getCreatedTimeMs());

			info = new OAuthClientInfo(UUID.randomUUID().toString(), UUID.randomUUID().toString(), name, desc, iconUrl, privacyUrl, ownerUid, now, callbacks);
			assertNotNull(info.getId());
			assertNotNull(info.getSecret());
			assertEquals(name, info.getName());
			assertTrue(info.getDescription().isPresent());
			assertEquals(desc, info.getDescription().get());
			assertTrue(info.getIconUrl().isPresent());
			assertEquals(iconUrl, info.getIconUrl().get());
			assertTrue(info.getPrivacyUrl().isPresent());
			assertEquals(privacyUrl, info.getPrivacyUrl().get());
			assertNotNull(info.getCallbacks());
			assertEquals(callbacks.size(), info.getCallbacks().size());
			assertEquals(callbacks.get(0), info.getCallbacks().get(0));
			assertEquals(ownerUid, info.getOwnerUid());
			assertEquals(now, info.getCreatedTimeMs());
		} catch (IllegalArgumentException e) {
			fail(e.getMessage());
		}
	}
}
