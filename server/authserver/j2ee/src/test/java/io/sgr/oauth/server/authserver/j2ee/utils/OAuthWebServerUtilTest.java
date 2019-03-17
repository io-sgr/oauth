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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.v20.OAuth20;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

@RunWith(MockitoJUnitRunner.class)
public class OAuthWebServerUtilTest {

    @Mock
    private HttpServletRequest mockReq;

    @Test
    public void testParseScope() throws InvalidRequestException, UnsupportedEncodingException {
        String scopes = "basic+additional";
        when(mockReq.getParameterValues(OAuth20.OAUTH_SCOPE)).thenReturn(new String[] {scopes});
        when(mockReq.getParameter(OAuth20.OAUTH_SCOPE)).thenReturn(scopes);
        List<String> parsed = OAuthWebServerUtil.parseScopes(mockReq, "\\ ").orElse(Collections.emptyList());
        assertEquals(2, parsed.size());
        scopes = " ";
        when(mockReq.getParameterValues(OAuth20.OAUTH_SCOPE)).thenReturn(new String[] {scopes});
        when(mockReq.getParameter(OAuth20.OAUTH_SCOPE)).thenReturn(scopes);
        parsed = OAuthWebServerUtil.parseScopes(mockReq, "\\ ").orElse(Collections.emptyList());
        assertEquals(0, parsed.size());
        scopes = ",";
        when(mockReq.getParameterValues(OAuth20.OAUTH_SCOPE)).thenReturn(new String[] {scopes});
        when(mockReq.getParameter(OAuth20.OAUTH_SCOPE)).thenReturn(scopes);
        parsed = OAuthWebServerUtil.parseScopes(mockReq).orElse(Collections.emptyList());
        assertEquals(0, parsed.size());
        scopes = URLEncoder.encode("basic,additional \n", "UTF-8");
        when(mockReq.getParameterValues(OAuth20.OAUTH_SCOPE)).thenReturn(new String[] {scopes});
        when(mockReq.getParameter(OAuth20.OAUTH_SCOPE)).thenReturn(scopes);
        parsed = OAuthWebServerUtil.parseScopes(mockReq).orElse(Collections.emptyList());
        assertEquals(2, parsed.size());
    }

    @Test
    public void testParseScopeWithIllegalArguments() throws InvalidRequestException {
        try {
            OAuthWebServerUtil.parseScopes(null, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            OAuthWebServerUtil.parseScopes(mockReq, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            OAuthWebServerUtil.parseScopes(mockReq, "\n");
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testGetOnlyOneParam() throws InvalidRequestException {
        final String param = "testKey";
        when(mockReq.getParameterValues(param)).thenReturn(new String[] {"", ""});
        try {
            OAuthWebServerUtil.getOnlyOneParameter(mockReq, param);
            fail();
        } catch (InvalidRequestException e) {
            // Expected
        }
        String value = "testValue";
        when(mockReq.getParameterValues(param)).thenReturn(new String[] {value});
        when(mockReq.getParameter(param)).thenReturn(value);
        Optional<String> parameter = OAuthWebServerUtil.getOnlyOneParameter(mockReq, param);
        assertTrue(parameter.isPresent());
        assertEquals(value, parameter.get());
        value = "\n";
        when(mockReq.getParameterValues(param)).thenReturn(new String[] {value});
        when(mockReq.getParameter(param)).thenReturn(value);
        parameter = OAuthWebServerUtil.getOnlyOneParameter(mockReq, param);
        assertFalse(parameter.isPresent());
        assertEquals("defaultValue", parameter.orElse("defaultValue"));
    }

    @Test
    public void testGetOnlyOneParamWithIllegalArguments() throws InvalidRequestException {
        try {
            OAuthWebServerUtil.getOnlyOneParameter(null, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            OAuthWebServerUtil.getOnlyOneParameter(mockReq, null);
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
        try {
            OAuthWebServerUtil.getOnlyOneParameter(mockReq, "\n");
            fail();
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

}
