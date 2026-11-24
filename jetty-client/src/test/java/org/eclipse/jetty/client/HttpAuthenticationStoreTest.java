//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.client;

import java.net.URI;

import org.eclipse.jetty.client.api.Authentication;
import org.eclipse.jetty.client.api.AuthenticationStore;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.BasicAuthentication;
import org.eclipse.jetty.client.util.DigestAuthentication;
import org.junit.Assert;
import org.junit.Test;

public class HttpAuthenticationStoreTest
{
    @Test
    public void testFindAuthenticationWithDefaultHTTPPort() throws Exception
    {
        AuthenticationStore store = new HttpAuthenticationStore();

        URI uri1 = URI.create("http://host:80");
        URI uri2 = URI.create("http://host");
        String realm = "realm";
        store.addAuthentication(new BasicAuthentication(uri1, realm, "user", "password"));

        Authentication result = store.findAuthentication("Basic", uri2, realm);
        Assert.assertNotNull(result);

        store.clearAuthentications();

        // Flip the URIs.
        uri1 = URI.create("https://server/");
        uri2 = URI.create("https://server:443/path");
        store.addAuthentication(new DigestAuthentication(uri1, realm, "user", "password"));
        result = store.findAuthentication("Digest", uri2, realm);
        Assert.assertNotNull(result);
    }

    @Test
    public void testFindAuthenticationWithURI()
    {
        String[][] cases =
        {
            // registered,             requested,                  matches
            {"http://host",            "http://host/any",          "true"},
            {"http://host/",           "http://host/any",          "true"},
            {"http://host/",           "http://HOST/any",          "true"},
            {"http://host/",           "http://host:80/any",       "true"},
            {"http://host/ctx/",       "http://host/ctx/",         "true"},
            {"http://host/ctx/",       "http://host/ctx",          "true"},
            {"http://host/ctx",        "http://host/ctx",          "true"},
            {"http://host/ctx",        "http://host/ctx/",         "true"},
            {"http://host/ctx",        "http://host/ctx/;j=1",     "true"},
            {"http://host/ctx",        "http://host/ctx?q=1",      "true"},
            {"http://host/ctx",        "http://host/ctx/?q=1",     "true"},
            {"http://host/ctx",        "http://host/ctx/path",     "true"},
            {"http://host/ctx",        "http://host/ctx//path",    "true"},
            {"http://host/ctx",        "http://host/c/../ctx/p",   "true"},
            {"http://host/ctx",        "http://host/ctx/p/../s",   "true"},
            {"http://host/ctx",        "http://host/ctx/./path",   "true"},
            {"http://host/ctx/~user",  "http://host/ctx/~user",    "true"},
            {"http://host/ctx/~user",  "http://host/ctx/%7Euser",  "true"},
            {"http://host/ctx%2Fp",    "http://host/ctx%2fp",      "true"},
            {"http://host/ctx%2Fp",    "http://host/ctx/p",        "false"},
            {"http://host/ctx",        "http://host/ctx2",         "false"},
            {"http://host/ctx/",       "http://host/ctx2",         "false"},
            {"http://host/ctx",        "http://host/ctx2/path",    "false"},
            {"http://host/ctx",        "http://host/c",            "false"},
            {"http://host/ctx",        "http://host/CTX",          "false"},
            {"http://host/ctx",        "http://host/ctx%2Fpath",   "false"},
            {"http://host/ctx",        "http://host/ctx/..",       "false"},
            {"http://host/ctx",        "http://host/ctx/../path",  "false"},
            {"http://host/ctx",        "http://host/ctx/..;/path", "false"},
            {"http://host/ctx/path",   "http://host/ctx",          "false"},
            {"http://host/ctx/path",   "http://host/ctx/",         "false"},
        };

        for (String[] c : cases)
            testFindAuthenticationWithURI(c[0], c[1], Boolean.parseBoolean(c[2]));
    }

    @Test
    public void testFindAuthenticationWithEncodedURI()
    {
        String[][] cases =
        {
            // registered,                 requested,                      matches
            {"http://host/ctx",            "http://host/ctx/%2E/path",     "true"},
            {"http://host/ctx",            "http://host/ctx/p/%2e%2e/s",   "true"},
            {"http://host/ctx/caf%C3%A9",  "http://host/ctx/caf%c3%a9/p",  "true"},
            {"http://host/ctx",            "http://host/ctx/%2E%2E",       "false"},
            {"http://host/ctx",            "http://host/ctx/%2E%2E/path",  "false"},
            {"http://host/ctx",            "http://host/ctx/%2e%2e;/path", "false"},
            {"http://host/ctx",            "http://host/ctx/.%2E/path",    "false"},
            {"http://host/ctx",            "http://host/ctx;p=1/../path",  "false"},
            {"http://host/ctx",            "http://host/ctx/../../path",   "false"},
            {"http://host/ctx",            "http://host/ctx%3B/path",      "false"},
        };

        for (String[] c : cases)
            testFindAuthenticationWithURI(c[0], c[1], Boolean.parseBoolean(c[2]));
    }

    private void testFindAuthenticationWithURI(String registered, String requested, boolean matches)
    {
        AuthenticationStore store = new HttpAuthenticationStore();

        URI uri1 = URI.create(registered);
        String realm = "realm";
        store.addAuthentication(new BasicAuthentication(uri1, realm, "user", "password"));

        URI uri2 = URI.create(requested);
        Authentication result = store.findAuthentication("Basic", uri2, realm);
        String message = "registered=" + registered + ", requested=" + requested + ", matches=" + matches;
        if (matches)
            Assert.assertNotNull(message, result);
        else
            Assert.assertNull(message, result);

        store.clearAuthentications();
    }

    @Test
    public void testFindAuthenticationResultWithURI()
    {
        String[][] cases =
        {
            // registered,         requested,                     matches
            {"http://host/ctx",    "http://host/ctx/path",        "true"},
            {"http://host/ctx",    "http://host/ctx2",            "false"},
            {"http://host/ctx",    "http://host/ctx/../path",     "false"},
            {"http://host/ctx",    "http://host/ctx/%2E%2E/path", "false"},
            {"http://host/ctx",    "http://host/ctx%2Fpath",      "false"},
        };

        for (String[] c : cases)
            testFindAuthenticationResultWithURI(c[0], c[1], Boolean.parseBoolean(c[2]));
    }

    private void testFindAuthenticationResultWithURI(String registered, String requested, boolean matches)
    {
        AuthenticationStore store = new HttpAuthenticationStore();

        final URI uri1 = URI.create(registered);
        store.addAuthenticationResult(new Authentication.Result()
        {
            @Override
            public URI getURI()
            {
                return uri1;
            }

            @Override
            public void apply(Request request)
            {
            }
        });

        URI uri2 = URI.create(requested);
        Authentication.Result result = store.findAuthenticationResult(uri2);
        String message = "registered=" + registered + ", requested=" + requested + ", matches=" + matches;
        if (matches)
            Assert.assertNotNull(message, result);
        else
            Assert.assertNull(message, result);

        store.clearAuthenticationResults();
    }

    @Test
    public void testFindAuthenticationResultWithDefaultHTTPPort() throws Exception
    {
        AuthenticationStore store = new HttpAuthenticationStore();

        store.addAuthenticationResult(new Authentication.Result()
        {
            @Override
            public URI getURI()
            {
                return URI.create("http://host:80");
            }

            @Override
            public void apply(Request request)
            {
            }
        });

        URI uri2 = URI.create("http://host");
        Authentication.Result result = store.findAuthenticationResult(uri2);
        Assert.assertNotNull(result);

        store.clearAuthenticationResults();

        // Flip the URIs.
        store.addAuthenticationResult(new Authentication.Result()
        {
            @Override
            public URI getURI()
            {
                return URI.create("https://server/");
            }

            @Override
            public void apply(Request request)
            {
            }
        });

        uri2 = URI.create("https://server:443/path");
        result = store.findAuthenticationResult(uri2);
        Assert.assertNotNull(result);
    }
}
