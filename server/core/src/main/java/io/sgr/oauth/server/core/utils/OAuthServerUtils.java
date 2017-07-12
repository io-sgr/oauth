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
package io.sgr.oauth.server.core.utils;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.utils.Preconditions;

/**
 * @author SgrAlpha
 *
 */
public class OAuthServerUtils {
	
	public static OAuthCredential parseAccessTokenFromAuthorization(String authStr) {
		if (Preconditions.isEmptyString(authStr)) {
			return null;
		}
		String[] a = authStr.split(" ");
		if (a.length != 2) {
			return null;
		}
		return new OAuthCredential(a[1], a[0]);
	}

}
