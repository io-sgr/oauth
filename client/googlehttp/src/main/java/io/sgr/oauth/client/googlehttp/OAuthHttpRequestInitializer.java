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

package io.sgr.oauth.client.googlehttp;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;

/**
 * @author SgrAlpha
 */
public class OAuthHttpRequestInitializer implements HttpRequestInitializer {

    /* (non-Javadoc)
     * @see com.google.api.client.http.HttpRequestInitializer#initialize(com.google.api.client.http.HttpRequest)
     */
    @Override
    public void initialize(HttpRequest request) {
        // request.setNumberOfRetries(3);
        request.setThrowExceptionOnExecuteError(false);
        // request.setParser(new JacksonFactory().createJsonObjectParser());
    }

}
