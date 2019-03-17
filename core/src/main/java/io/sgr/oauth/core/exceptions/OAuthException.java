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

import io.sgr.oauth.core.v20.OAuthError;

import java.text.MessageFormat;

/**
 * @author SgrAlpha
 */
public abstract class OAuthException extends Exception {

    private final OAuthError error;

    /**
     * @param error
     *         The OAuth error
     */
    public OAuthException(OAuthError error) {
        super();
        this.error = error;
    }

    public OAuthException(final OAuthError error, final Throwable cause) {
        super(cause);
        this.error = error;
    }

    /* (non-Javadoc)
     * @see java.lang.Throwable#getMessage()
     */
    @Override
    public String getMessage() {
        if (this.getError() == null) {
            return "No more detail";
        }
        return this.getError().getErrorDescription() == null ?
                this.getError().getName() :
                MessageFormat.format("{0}: {1}", this.getError().getName(), this.getError().getErrorDescription());
    }

    /**
     * @return the error
     * The OAuth error
     */
    public OAuthError getError() {
        return this.error;
    }

    /**
     *
     */
    private static final long serialVersionUID = -4355086515711493909L;

}
