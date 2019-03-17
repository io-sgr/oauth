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

package io.sgr.oauth.server.authserver.j2ee.utils;

public class OAuthV2WebConstants {

    public static final String DEFAULT_SCOPE_SPLITTER = ",";

    public static final String SESSION_ATTRS_KEY_AUTH_DETAIL = "oauth.v2.auth_detail";
    public static final String SESSION_ATTRS_KEY_CSRF_TOKEN = "csrf_token";

    public static final String REQ_PARAMS_KEY_CSRF_TOKEN = "csrf_token";
    public static final String REQ_PARAMS_KEY_APPROVED = "approved";

}
