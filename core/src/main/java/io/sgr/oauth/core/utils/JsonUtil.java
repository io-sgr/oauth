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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;

/**
 * @author SgrAlpha
 */
public class JsonUtil {

    private static final DateFormat DEFAULT_DATE_FORMAT = new SimpleDateFormat("E MMM dd HH:mm:ss Z yyyy", Locale.US);

    private static final JsonFactory JSON_FACTORY = new JsonFactory();

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(JSON_FACTORY);

    /**
     * @return the defaultDateFormat
     */
    public static DateFormat getDefaultDateFormat() {
        return DEFAULT_DATE_FORMAT;
    }

    /**
     * @return the jsonFactory
     */
    public static JsonFactory getJsonFactory() {
        return JSON_FACTORY;
    }

    /**
     * @return the objectMapper
     */
    public static ObjectMapper getObjectMapper() {
        return OBJECT_MAPPER;
    }

}
