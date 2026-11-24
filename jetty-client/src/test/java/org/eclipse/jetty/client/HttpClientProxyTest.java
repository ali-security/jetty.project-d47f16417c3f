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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.BasicAuthentication;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.IO;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.Assert;
import org.junit.Test;

public class HttpClientProxyTest extends AbstractHttpClientServerTest
{
    public HttpClientProxyTest(SslContextFactory sslContextFactory)
    {
        // Avoid TLS otherwise CONNECT requests are sent instead of proxied requests
        super(null);
    }

    @Test
    public void testProxiedRequest() throws Exception
    {
        final String serverHost = "server";
        final int status = HttpStatus.NO_CONTENT_204;
        start(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                if (!URI.create(baseRequest.getHttpURI().toString()).isAbsolute())
                    response.setStatus(HttpServletResponse.SC_USE_PROXY);
                else if (serverHost.equals(request.getServerName()))
                    response.setStatus(status);
                else
                    response.setStatus(HttpServletResponse.SC_NOT_ACCEPTABLE);
            }
        });

        int proxyPort = connector.getLocalPort();
        int serverPort = proxyPort + 1; // Any port will do for these tests - just not the same as the proxy
        client.getProxyConfiguration().getProxies().add(new HttpProxy("localhost", proxyPort));

        ContentResponse response = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response.getStatus());
    }

    @Test
    public void testProxyAuthentication() throws Exception
    {
        final String user = "foo";
        final String password = "bar";
        final String credentials = B64Code.encode(user + ":" + password, StandardCharsets.ISO_8859_1);
        final String serverHost = "server";
        final String realm = "test_realm";
        final int status = HttpStatus.NO_CONTENT_204;
        start(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.setHeader(HttpHeader.PROXY_AUTHENTICATE.asString(), "Basic realm=\"" + realm + "\"");
                }
                else
                {
                    String prefix = "Basic ";
                    if (authorization.startsWith(prefix))
                    {
                        String attempt = authorization.substring(prefix.length());
                        if (credentials.equals(attempt))
                            response.setStatus(status);
                    }
                }
            }
        });

        String proxyHost = "localhost";
        int proxyPort = connector.getLocalPort();
        int serverPort = proxyPort + 1; // Any port will do for these tests - just not the same as the proxy
        client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxyPort));

        ContentResponse response1 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        // No Authentication available => 407
        Assert.assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response1.getStatus());

        // Add authentication...
        URI uri = URI.create(scheme + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(uri, realm, user, password));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().add(new Request.Listener.Adapter()
        {
            @Override
            public void onSuccess(Request request)
            {
                requests.incrementAndGet();
            }
        });
        // ...and perform the request again => 407 + 204
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response2.getStatus());
        Assert.assertEquals(2, requests.get());

        // Now the authentication result is cached => 204
        requests.set(0);
        ContentResponse response3 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response3.getStatus());
        Assert.assertEquals(1, requests.get());
    }

    @Test
    public void testProxyAuthenticationWithRedirect() throws Exception
    {
        String user = "foo";
        String password = "bar";
        String credentials = B64Code.encode(user + ":" + password, StandardCharsets.ISO_8859_1);
        String proxyHost = "localhost";
        String serverHost = "server";
        int serverPort = HttpScheme.HTTP.is(scheme) ? 80 : 443;
        String realm = "test_realm";
        int status = HttpStatus.NO_CONTENT_204;
        start(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                if (target.startsWith("/proxy"))
                {
                    String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                    if (authorization == null)
                    {
                        response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                        response.setHeader(HttpHeader.PROXY_AUTHENTICATE.asString(), "Basic realm=\"" + realm + "\"");
                    }
                    else
                    {
                        String prefix = "Basic ";
                        if (authorization.startsWith(prefix))
                        {
                            String attempt = authorization.substring(prefix.length());
                            if (credentials.equals(attempt))
                            {
                                // Change also the host, to verify that proxy authentication works in this case too.
                                response.sendRedirect(scheme + "://127.0.0.1:" + serverPort + "/server");
                            }
                        }
                    }
                }
                else if (target.startsWith("/server"))
                {
                    response.setStatus(status);
                }
                else
                {
                    response.sendError(HttpStatus.INTERNAL_SERVER_ERROR_500);
                }
            }
        });

        int proxyPort = connector.getLocalPort();
        client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxyPort));

        ContentResponse response1 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .path("/proxy")
                .timeout(5, TimeUnit.SECONDS)
                .send();

        // No Authentication available => 407.
        Assert.assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response1.getStatus());

        // Add authentication...
        URI uri = URI.create(scheme + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(uri, realm, user, password));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().add(new Request.Listener.Adapter()
        {
            @Override
            public void onSuccess(Request request)
            {
                requests.incrementAndGet();
            }
        });
        // ...and perform the request again => 407 + 302 + 204.
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .path("/proxy")
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response2.getStatus());
        Assert.assertEquals(3, requests.get());

        // Now the authentication result is cached => 204.
        requests.set(0);
        ContentResponse response3 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .path("/server")
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response3.getStatus());
        Assert.assertEquals(1, requests.get());
    }

    @Test
    public void testProxyAuthenticationWithServerAuthentication() throws Exception
    {
        String proxyRealm = "proxyRealm";
        String serverRealm = "serverRealm";
        int status = HttpStatus.NO_CONTENT_204;
        start(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.setHeader(HttpHeader.PROXY_AUTHENTICATE.asString(), "Basic realm=\"" + proxyRealm + "\"");
                }
                else
                {
                    authorization = request.getHeader(HttpHeader.AUTHORIZATION.asString());
                    if (authorization == null)
                    {
                        response.setStatus(HttpStatus.UNAUTHORIZED_401);
                        response.setHeader(HttpHeader.WWW_AUTHENTICATE.asString(), "Basic realm=\"" + serverRealm + "\"");
                    }
                    else
                    {
                        response.setStatus(status);
                    }
                }
            }
        });

        String proxyHost = "localhost";
        int proxyPort = connector.getLocalPort();
        String serverHost = "server";
        int serverPort = proxyPort + 1;
        URI proxyURI = URI.create(scheme + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, proxyRealm, "proxyUser", "proxyPassword"));
        URI serverURI = URI.create(scheme + "://" + serverHost + ":" + serverPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(serverURI, serverRealm, "serverUser", "serverPassword"));
        client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxyPort));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().add(new Request.Listener.Adapter()
        {
            @Override
            public void onSuccess(Request request)
            {
                requests.incrementAndGet();
            }
        });
        // Make a request, expect 407 + 401 + 204.
        ContentResponse response1 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response1.getStatus());
        Assert.assertEquals(3, requests.get());

        // Make again the request, authentication is cached, expect 204.
        requests.set(0);
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response2.getStatus());
        Assert.assertEquals(1, requests.get());
    }

    @Test
    public void testProxyAuthenticationWithExplicitAuthorizationHeader() throws Exception
    {
        String proxyRealm = "proxyRealm";
        String serverRealm = "serverRealm";
        int status = HttpStatus.NO_CONTENT_204;
        start(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.setHeader(HttpHeader.PROXY_AUTHENTICATE.asString(), "Basic realm=\"" + proxyRealm + "\"");
                }
                else
                {
                    authorization = request.getHeader(HttpHeader.AUTHORIZATION.asString());
                    if (authorization == null)
                    {
                        response.setStatus(HttpStatus.UNAUTHORIZED_401);
                        response.setHeader(HttpHeader.WWW_AUTHENTICATE.asString(), "Basic realm=\"" + serverRealm + "\"");
                    }
                    else
                    {
                        response.setStatus(status);
                    }
                }
            }
        });

        String proxyHost = "localhost";
        int proxyPort = connector.getLocalPort();
        String serverHost = "server";
        int serverPort = proxyPort + 1;
        URI proxyURI = URI.create(scheme + "://" + proxyHost + ":" + proxyPort);
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, proxyRealm, "proxyUser", "proxyPassword"));
        client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxyPort));
        final AtomicInteger requests = new AtomicInteger();
        client.getRequestListeners().add(new Request.Listener.Adapter()
        {
            @Override
            public void onSuccess(Request request)
            {
                requests.incrementAndGet();
            }
        });
        // Make a request, expect 407 + 204.
        ContentResponse response1 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .header(HttpHeader.AUTHORIZATION, "Basic foobar")
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response1.getStatus());
        Assert.assertEquals(2, requests.get());

        // Make again the request, authentication is cached, expect 204.
        requests.set(0);
        ContentResponse response2 = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .header(HttpHeader.AUTHORIZATION, "Basic foobar")
                .timeout(5, TimeUnit.SECONDS)
                .send();

        Assert.assertEquals(status, response2.getStatus());
        Assert.assertEquals(1, requests.get());
    }

    @Test
    public void testProxiedRequestWithRelativePathLikeAuthority() throws Exception
    {
        final String serverHost = "server";
        final String path = ";@host.org/url";
        final int status = HttpStatus.NO_CONTENT_204;
        start(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                if (!URI.create(baseRequest.getHttpURI().toString()).isAbsolute())
                    response.setStatus(HttpServletResponse.SC_USE_PROXY);
                else if (serverHost.equals(request.getServerName()) && ("/" + path).equals(request.getRequestURI()))
                    response.setStatus(status);
                else
                    response.setStatus(HttpServletResponse.SC_NOT_ACCEPTABLE);
            }
        });

        int proxyPort = connector.getLocalPort();
        int serverPort = proxyPort + 1; // Any port will do for these tests - just not the same as the proxy
        client.getProxyConfiguration().getProxies().add(new HttpProxy("localhost", proxyPort));

        // The relative path must not be able to change the
        // authority of the absolute-form target sent to the proxy.
        Request request = client.newRequest(serverHost, serverPort)
                .scheme(scheme)
                .path(path)
                .timeout(5, TimeUnit.SECONDS);

        Assert.assertEquals("/" + path, request.getPath());
        Assert.assertEquals(serverHost, request.getURI().getHost());
        Assert.assertEquals(serverPort, request.getURI().getPort());

        ContentResponse response = request.send();

        Assert.assertEquals(status, response.getStatus());
    }

    @Test
    public void testServerProxyAuthenticationChallengeInTunnelIsNotAnswered() throws Exception
    {
        String realm = "proxyRealm";
        List<String> serverProxyAuthorizations = new CopyOnWriteArrayList<>();
        AtomicInteger serverRequests = new AtomicInteger();
        // A malicious server replies with a 407 from inside the
        // tunnel, pretending to be the proxy, to obtain the proxy credentials.
        startTLS(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            {
                baseRequest.setHandled(true);
                serverRequests.incrementAndGet();
                String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.setHeader(HttpHeader.PROXY_AUTHENTICATE.asString(), "Basic realm=\"" + realm + "\"");
                }
                else
                {
                    serverProxyAuthorizations.add(authorization);
                }
            }
        });

        // The proxy does not require authentication.
        try (TunnelProxy proxy = new TunnelProxy(connect -> null))
        {
            String proxyHost = "localhost";
            client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxy.getPort()));
            URI proxyURI = URI.create(HttpScheme.HTTP.asString() + "://" + proxyHost + ":" + proxy.getPort());
            client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, realm, "proxyUser", "proxyPassword"));

            ContentResponse response = client.newRequest("localhost", connector.getLocalPort())
                    .scheme(HttpScheme.HTTPS.asString())
                    .timeout(5, TimeUnit.SECONDS)
                    .send();

            // The 407 does not come from the proxy, so it must be returned to the application.
            Assert.assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response.getStatus());
            Assert.assertEquals(1, proxy.getConnectRequests().size());
            Assert.assertEquals(1, serverRequests.get());
            // The proxy credentials must not be sent to the server.
            Assert.assertTrue(serverProxyAuthorizations.toString(), serverProxyAuthorizations.isEmpty());
        }
    }

    @Test
    public void testProxyAuthenticationIsNotSentToServerInTunnel() throws Exception
    {
        String realm = "proxyRealm";
        String user = "proxyUser";
        String password = "proxyPassword";
        String credentials = "Basic " + B64Code.encode(user + ":" + password, StandardCharsets.ISO_8859_1);
        List<String> serverProxyAuthorizations = new CopyOnWriteArrayList<>();
        startTLS(new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            {
                baseRequest.setHandled(true);
                String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization != null)
                    serverProxyAuthorizations.add(authorization);
            }
        });

        // The proxy requires authentication to establish the tunnel.
        String challenge = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
                "Proxy-Authenticate: Basic realm=\"" + realm + "\"\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n";
        try (TunnelProxy proxy = new TunnelProxy(connect -> credentials.equals(connect.proxyAuthorization) ? null : challenge))
        {
            String proxyHost = "localhost";
            client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxy.getPort()));
            URI proxyURI = URI.create(HttpScheme.HTTP.asString() + "://" + proxyHost + ":" + proxy.getPort());
            client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, realm, user, password));

            // Expect CONNECT + 407, CONNECT + 200, then the request tunnelled to the server.
            ContentResponse response1 = client.newRequest("localhost", connector.getLocalPort())
                    .scheme(HttpScheme.HTTPS.asString())
                    .timeout(5, TimeUnit.SECONDS)
                    .send();

            Assert.assertEquals(HttpStatus.OK_200, response1.getStatus());
            List<ConnectRequest> connects = proxy.getConnectRequests();
            Assert.assertEquals(2, connects.size());
            Assert.assertNull(connects.get(0).proxyAuthorization);
            Assert.assertEquals(credentials, connects.get(1).proxyAuthorization);

            // A request to a different destination needs a new tunnel,
            // that is established with the cached proxy authentication.
            ContentResponse response2 = client.newRequest("127.0.0.1", connector.getLocalPort())
                    .scheme(HttpScheme.HTTPS.asString())
                    .timeout(5, TimeUnit.SECONDS)
                    .send();

            Assert.assertEquals(HttpStatus.OK_200, response2.getStatus());
            connects = proxy.getConnectRequests();
            Assert.assertEquals(3, connects.size());
            Assert.assertEquals(credentials, connects.get(2).proxyAuthorization);

            // The proxy credentials must never be sent to the server.
            Assert.assertTrue(serverProxyAuthorizations.toString(), serverProxyAuthorizations.isEmpty());
        }
    }

    @Test
    public void testServerAuthenticationChallengeFromProxyToTunnelRequestIsNotAnswered() throws Exception
    {
        String realm = "serverRealm";
        startTLS(new EmptyServerHandler());

        // The proxy replies to the CONNECT request with a 401, rather than a 407.
        String challenge = "HTTP/1.1 401 Unauthorized\r\n" +
                "WWW-Authenticate: Basic realm=\"" + realm + "\"\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n";
        try (TunnelProxy proxy = new TunnelProxy(connect -> challenge))
        {
            String proxyHost = "localhost";
            client.getProxyConfiguration().getProxies().add(new HttpProxy(proxyHost, proxy.getPort()));
            URI proxyURI = URI.create(HttpScheme.HTTP.asString() + "://" + proxyHost + ":" + proxy.getPort());
            client.getAuthenticationStore().addAuthentication(new BasicAuthentication(proxyURI, realm, "serverUser", "serverPassword"));

            try
            {
                client.newRequest("localhost", connector.getLocalPort())
                        .scheme(HttpScheme.HTTPS.asString())
                        .timeout(5, TimeUnit.SECONDS)
                        .send();
                Assert.fail("The tunnel must not be established");
            }
            catch (ExecutionException expected)
            {
                // The CONNECT request failed with the 401.
            }

            // The 401 must not be handled as a server authentication challenge,
            // so the server credentials must never be sent to the proxy.
            List<ConnectRequest> connects = proxy.getConnectRequests();
            Assert.assertFalse(connects.isEmpty());
            for (ConnectRequest connect : connects)
            {
                Assert.assertNull(connect.authorization);
            }
        }
    }

    @Test
    public void testServerProxyAuthenticationChallengeWithoutProxyIsNotAnswered() throws Exception
    {
        testServerProxyAuthenticationChallengeWithoutProxyIsNotAnswered(false);
    }

    @Test
    public void testServerProxyAuthenticationChallengeWithoutProxyOverTLSIsNotAnswered() throws Exception
    {
        testServerProxyAuthenticationChallengeWithoutProxyIsNotAnswered(true);
    }

    private void testServerProxyAuthenticationChallengeWithoutProxyIsNotAnswered(boolean secure) throws Exception
    {
        String realm = "proxyRealm";
        List<String> serverProxyAuthorizations = new CopyOnWriteArrayList<>();
        AtomicInteger serverRequests = new AtomicInteger();
        Handler handler = new AbstractHandler()
        {
            @Override
            public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            {
                baseRequest.setHandled(true);
                serverRequests.incrementAndGet();
                String authorization = request.getHeader(HttpHeader.PROXY_AUTHORIZATION.asString());
                if (authorization == null)
                {
                    response.setStatus(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407);
                    response.setHeader(HttpHeader.PROXY_AUTHENTICATE.asString(), "Basic realm=\"" + realm + "\"");
                }
                else
                {
                    serverProxyAuthorizations.add(authorization);
                }
            }
        };
        if (secure)
            startTLS(handler);
        else
            start(handler);

        // No proxy is configured, so the request is sent directly to the server.
        URI serverURI = URI.create(scheme + "://localhost:" + connector.getLocalPort());
        client.getAuthenticationStore().addAuthentication(new BasicAuthentication(serverURI, realm, "user", "password"));

        ContentResponse response = client.newRequest("localhost", connector.getLocalPort())
                .scheme(scheme)
                .timeout(5, TimeUnit.SECONDS)
                .send();

        // The 407 does not come from a proxy, so it must be returned to the application.
        Assert.assertEquals(HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407, response.getStatus());
        Assert.assertEquals(1, serverRequests.get());
        Assert.assertTrue(serverProxyAuthorizations.toString(), serverProxyAuthorizations.isEmpty());
    }

    private void startTLS(Handler handler) throws Exception
    {
        // Use TLS, so that requests are tunnelled via CONNECT through the proxy.
        sslContextFactory = new SslContextFactory();
        scheme = HttpScheme.HTTPS.asString();
        start(handler);
    }

    private static class ConnectRequest
    {
        private final String target;
        private String proxyAuthorization;
        private String authorization;

        private ConnectRequest(String target)
        {
            this.target = target;
        }
    }

    /**
     * <p>A minimal HTTP proxy that only supports tunnelling via {@code CONNECT}.</p>
     * <p>The given function is invoked for every {@code CONNECT} request: if it returns
     * {@code null} the tunnel is established, otherwise its result is written as the
     * response, and the proxy waits for another {@code CONNECT} request.</p>
     */
    private static class TunnelProxy implements Closeable
    {
        private final List<ConnectRequest> connectRequests = new CopyOnWriteArrayList<>();
        private final ExecutorService executor = Executors.newCachedThreadPool();
        private final Function<ConnectRequest, String> handler;
        private final ServerSocket serverSocket;

        private TunnelProxy(Function<ConnectRequest, String> handler) throws IOException
        {
            this.handler = handler;
            this.serverSocket = new ServerSocket(0);
            executor.execute(this::acceptLoop);
        }

        private int getPort()
        {
            return serverSocket.getLocalPort();
        }

        private List<ConnectRequest> getConnectRequests()
        {
            return connectRequests;
        }

        private void acceptLoop()
        {
            while (true)
            {
                try
                {
                    Socket socket = serverSocket.accept();
                    executor.execute(() -> handle(socket));
                }
                catch (Throwable x)
                {
                    return;
                }
            }
        }

        private void handle(Socket client)
        {
            try
            {
                InputStream clientInput = client.getInputStream();
                OutputStream clientOutput = client.getOutputStream();
                while (true)
                {
                    ConnectRequest connect = readConnectRequest(clientInput);
                    if (connect == null)
                        break;
                    connectRequests.add(connect);

                    String response = handler.apply(connect);
                    if (response != null)
                    {
                        clientOutput.write(response.getBytes(StandardCharsets.ISO_8859_1));
                        clientOutput.flush();
                        continue;
                    }

                    int colon = connect.target.lastIndexOf(':');
                    String host = connect.target.substring(0, colon);
                    int port = Integer.parseInt(connect.target.substring(colon + 1));
                    Socket server = new Socket(host, port);
                    clientOutput.write("HTTP/1.1 200 OK\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                    clientOutput.flush();
                    executor.execute(() -> pump(clientInput, server, client, server));
                    pump(server.getInputStream(), client, client, server);
                    return;
                }
            }
            catch (Throwable ignored)
            {
                // The connection will be closed below.
            }
            IO.close(client);
        }

        private void pump(InputStream input, Socket target, Socket... sockets)
        {
            try
            {
                OutputStream output = target.getOutputStream();
                byte[] buffer = new byte[4096];
                while (true)
                {
                    int read = input.read(buffer);
                    if (read < 0)
                        break;
                    output.write(buffer, 0, read);
                    output.flush();
                }
            }
            catch (Throwable ignored)
            {
                // The sockets will be closed below.
            }
            for (Socket socket : sockets)
            {
                IO.close(socket);
            }
        }

        private ConnectRequest readConnectRequest(InputStream input) throws IOException
        {
            String requestLine = readLine(input);
            if (requestLine == null)
                return null;
            String[] parts = requestLine.split(" ");
            if (parts.length != 3 || !HttpMethod.CONNECT.is(parts[0]))
                throw new IOException("Unexpected request: " + requestLine);
            ConnectRequest connect = new ConnectRequest(parts[1]);
            while (true)
            {
                String line = readLine(input);
                if (line == null)
                    return null;
                if (line.isEmpty())
                    return connect;
                int colon = line.indexOf(':');
                if (colon < 0)
                    continue;
                String name = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                if (HttpHeader.PROXY_AUTHORIZATION.is(name))
                    connect.proxyAuthorization = value;
                else if (HttpHeader.AUTHORIZATION.is(name))
                    connect.authorization = value;
            }
        }

        private String readLine(InputStream input) throws IOException
        {
            StringBuilder builder = new StringBuilder();
            while (true)
            {
                int read = input.read();
                if (read < 0)
                    return null;
                if (read == '\n')
                {
                    int length = builder.length();
                    if (length > 0 && builder.charAt(length - 1) == '\r')
                        builder.setLength(length - 1);
                    return builder.toString();
                }
                builder.append((char)read);
            }
        }

        @Override
        public void close()
        {
            IO.close(serverSocket);
            executor.shutdownNow();
        }
    }
}
