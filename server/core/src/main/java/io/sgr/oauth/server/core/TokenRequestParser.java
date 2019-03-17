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

package io.sgr.oauth.server.core;

import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.server.core.models.TokenRequest;

public interface TokenRequestParser<T> {

    TokenRequest parse(T from) throws InvalidRequestException, InvalidGrantException, UnsupportedGrantTypeException;

}
