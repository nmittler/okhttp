/*
 * Copyright (C) 2012 Square, Inc.
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.squareup.okhttp.internal;

import com.squareup.okhttp.Protocol;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DeflaterOutputStream;
import javax.net.ssl.SSLSocket;
import okio.ByteString;

/**
 * Access to Platform-specific features necessary for SPDY and advanced TLS.
 *
 * <h3>ALPN</h3>
 * This class uses the ALPN TLS extension to negotiate the upgrade from
 * HTTP/1.1 (the default protocol to use with TLS on port 443) to either SPDY
 * or HTTP/2.
 */
public class Platform {
  private static final Platform PLATFORM = findPlatform();

  private Constructor<DeflaterOutputStream> deflaterConstructor;

  public static Platform get() {
    return PLATFORM;
  }

  /** Prefix used on custom headers. */
  public String getPrefix() {
    return "OkHttp";
  }

  public void logW(String warning) {
    System.out.println(warning);
  }

  public void tagSocket(Socket socket) throws SocketException {
  }

  public void untagSocket(Socket socket) throws SocketException {
  }

  public URI toUriLenient(URL url) throws URISyntaxException {
    return url.toURI(); // this isn't as good as the built-in toUriLenient
  }

  /**
   * Attempt a TLS connection with useful extensions enabled. This mode
   * supports more features, but is less likely to be compatible with older
   * HTTPS servers.
   */
  public void enableTlsExtensions(SSLSocket socket, String uriHost) {
  }

  /**
   * Attempt a secure connection with basic functionality to maximize
   * compatibility. Currently this uses SSL 3.0.
   */
  public void supportTlsIntolerantServer(SSLSocket socket) {
    socket.setEnabledProtocols(new String[] {"SSLv3"});
  }

  /** Returns the negotiated protocol, or null if no protocol was negotiated. */
  public ByteString getAlpnSelectedProtocol(SSLSocket socket) {
    return null;
  }

  /**
   * Sets client-supported protocols on a socket to send to a server. The
   * protocols are only sent if the socket implementation supports ALPN.
   */
  public void setAlpnProtocols(SSLSocket socket, List<Protocol> alpnProtocols) {
  }

  public void connectSocket(Socket socket, InetSocketAddress address,
      int connectTimeout) throws IOException {
    socket.connect(address, connectTimeout);
  }

  /** Attempt to match the host runtime to a capable Platform implementation. */
  private static Platform findPlatform() {
    // Attempt to find Android 2.3+ APIs.
    Class<?> openSslSocketClass;
    Method setUseSessionTickets;
    Method setHostname;
    try {
      try {
        openSslSocketClass = Class.forName("com.android.org.conscrypt.OpenSSLSocketImpl");
      } catch (ClassNotFoundException ignored) {
        // Older platform before being unbundled.
        openSslSocketClass = Class.forName(
            "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl");
      }

      setUseSessionTickets = openSslSocketClass.getMethod("setUseSessionTickets", boolean.class);
      setHostname = openSslSocketClass.getMethod("setHostname", String.class);

      // Attempt to find Android 4.1+ APIs.
      Method setNpnProtocols = null;
      Method getNpnSelectedProtocol = null;
      try {
        setNpnProtocols = openSslSocketClass.getMethod("setNpnProtocols", byte[].class);
        getNpnSelectedProtocol = openSslSocketClass.getMethod("getNpnSelectedProtocol");
      } catch (NoSuchMethodException ignored) {
      }

      return new Android(openSslSocketClass, setUseSessionTickets, setHostname, setNpnProtocols,
          getNpnSelectedProtocol);
    } catch (ClassNotFoundException ignored) {
      // This isn't an Android runtime.
    } catch (NoSuchMethodException ignored) {
      // This isn't Android 2.3 or better.
    }

    // Attempt to find the Jetty's ALPN extension for OpenJDK.
    try {
      String alpnClassName = "org.eclipse.jetty.alpn.ALPN";
      Class<?> alpnClass = Class.forName(alpnClassName);
      Class<?> providerClass = Class.forName(alpnClassName + "$Provider");
      Class<?> clientProviderClass = Class.forName(alpnClassName + "$ClientProvider");
      Class<?> serverProviderClass = Class.forName(alpnClassName + "$ServerProvider");
      Method putMethod = alpnClass.getMethod("put", SSLSocket.class, providerClass);
      Method getMethod = alpnClass.getMethod("get", SSLSocket.class);
      return new JdkWithJettyAlpnPlatform(
          putMethod, getMethod, clientProviderClass, serverProviderClass);
    } catch (ClassNotFoundException ignored) {
      // ALPN isn't on the classpath.
    } catch (NoSuchMethodException ignored) {
      // The ALPN version isn't what we expect.
    }

    return new Platform();
  }

  /**
   * Android 2.3 or better. Version 2.3 supports TLS session tickets and server
   * name indication (SNI). Versions 4.1 supports ALPN.
   */
  private static class Android extends Platform {
    // Non-null.
    protected final Class<?> openSslSocketClass;
    private final Method setUseSessionTickets;
    private final Method setHostname;

    // Non-null on Android 4.1+.
    private final Method setNpnProtocols;
    private final Method getNpnSelectedProtocol;

    private Android(Class<?> openSslSocketClass, Method setUseSessionTickets, Method setHostname,
        Method setNpnProtocols, Method getNpnSelectedProtocol) {
      this.openSslSocketClass = openSslSocketClass;
      this.setUseSessionTickets = setUseSessionTickets;
      this.setHostname = setHostname;
      this.setNpnProtocols = setNpnProtocols;
      this.getNpnSelectedProtocol = getNpnSelectedProtocol;
    }

    @Override public void connectSocket(Socket socket, InetSocketAddress address,
        int connectTimeout) throws IOException {
      try {
        socket.connect(address, connectTimeout);
      } catch (SecurityException se) {
        // Before android 4.3, socket.connect could throw a SecurityException
        // if opening a socket resulted in an EACCES error.
        IOException ioException = new IOException("Exception in connect");
        ioException.initCause(se);
        throw ioException;
      }
    }

    @Override public void enableTlsExtensions(SSLSocket socket, String uriHost) {
      super.enableTlsExtensions(socket, uriHost);
      if (!openSslSocketClass.isInstance(socket)) return;
      try {
        setUseSessionTickets.invoke(socket, true);
        setHostname.invoke(socket, uriHost);
      } catch (InvocationTargetException e) {
        throw new RuntimeException(e);
      } catch (IllegalAccessException e) {
        throw new AssertionError(e);
      }
    }

    @Override public void setAlpnProtocols(SSLSocket socket, List<Protocol> alpnProtocols) {
      if (setNpnProtocols == null) return;
      if (!openSslSocketClass.isInstance(socket)) return;
      try {
        Object[] parameters = { concatLengthPrefixed(alpnProtocols) };
        setNpnProtocols.invoke(socket, parameters);
      } catch (IllegalAccessException e) {
        throw new AssertionError(e);
      } catch (InvocationTargetException e) {
        throw new RuntimeException(e);
      }
    }

    @Override public ByteString getAlpnSelectedProtocol(SSLSocket socket) {
      if (getNpnSelectedProtocol == null) return null;
      if (!openSslSocketClass.isInstance(socket)) return null;
      try {
        byte[] npnResult = (byte[]) getNpnSelectedProtocol.invoke(socket);
        if (npnResult == null) return null;
        return ByteString.of(npnResult);
      } catch (InvocationTargetException e) {
        throw new RuntimeException(e);
      } catch (IllegalAccessException e) {
        throw new AssertionError(e);
      }
    }
  }

  /** OpenJDK 7 plus {@code org.mortbay.jetty.alpn/alpn-boot} on the boot class path. */
  private static class JdkWithJettyAlpnPlatform extends Platform {
    private final Method getMethod;
    private final Method putMethod;
    private final Class<?> clientProviderClass;
    private final Class<?> serverProviderClass;

    public JdkWithJettyAlpnPlatform(Method putMethod, Method getMethod,
        Class<?> clientProviderClass, Class<?> serverProviderClass) {
      this.putMethod = putMethod;
      this.getMethod = getMethod;
      this.clientProviderClass = clientProviderClass;
      this.serverProviderClass = serverProviderClass;
    }

    @Override public void setAlpnProtocols(SSLSocket socket, List<Protocol> alpnProtocols) {
      try {
        List<String> names = new ArrayList<String>(alpnProtocols.size());
        for (int i = 0, size = alpnProtocols.size(); i < size; i++) {
          names.add(alpnProtocols.get(i).name.utf8());
        }
        Object provider = Proxy.newProxyInstance(Platform.class.getClassLoader(),
            new Class[] { clientProviderClass, serverProviderClass }, new JettyAlpnProvider(names));
        putMethod.invoke(null, socket, provider);
      } catch (InvocationTargetException e) {
        throw new AssertionError(e);
      } catch (IllegalAccessException e) {
        throw new AssertionError(e);
      }
    }

    @Override public ByteString getAlpnSelectedProtocol(SSLSocket socket) {
      try {
        JettyAlpnProvider provider =
            (JettyAlpnProvider) Proxy.getInvocationHandler(getMethod.invoke(null, socket));
        if (!provider.unsupported && provider.selected == null) {
          Logger logger = Logger.getLogger("com.squareup.okhttp.OkHttpClient");
          logger.log(Level.INFO,
              "ALPN callback dropped so SPDY is disabled. Is alpn-boot on the boot class path?");
          return null;
        }
        return provider.unsupported ? null : ByteString.encodeUtf8(provider.selected);
      } catch (InvocationTargetException e) {
        throw new AssertionError();
      } catch (IllegalAccessException e) {
        throw new AssertionError();
      }
    }
  }

  /**
   * Handle the methods of ALPN's ClientProvider and ServerProvider
   * without a compile-time dependency on those interfaces.
   */
  private static class JettyAlpnProvider implements InvocationHandler {
    /** This peer's supported protocols. */
    private final List<String> protocols;
    /** Set when remote peer notifies ALPN is unsupported. */
    private boolean unsupported;
    /** The protocol the server selected. */
    private String selected;

    public JettyAlpnProvider(List<String> protocols) {
      this.protocols = protocols;
    }

    @Override public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      String methodName = method.getName();
      Class<?> returnType = method.getReturnType();
      if (args == null) {
        args = Util.EMPTY_STRING_ARRAY;
      }
      if (methodName.equals("supports") && boolean.class == returnType) {
        return true; // Client supports ALPN.
      } else if (methodName.equals("unsupported") && void.class == returnType) {
        this.unsupported = true; // Remote peer doesn't support ALPN.
        return null;
      } else if (methodName.equals("protocols") && args.length == 0) {
        return protocols; // Client advertises these protocols.
      } else if (methodName.equals("select") // Called when server.
          && String.class == returnType
          && args.length == 1
          && (args[0] == null || args[0] instanceof List)) {
        List<String> serverProtocols = (List) args[0];
        // Pick the first protocol the client advertises and server knows.
        for (int i = 0, size = serverProtocols.size(); i < size; i++) {
          if (protocols.contains(serverProtocols.get(i))) {
            return selected = serverProtocols.get(i);
          }
        }
        // On no intersection, try server's first protocol.
        return selected = protocols.get(0);
      } else if (methodName.equals("selected") && args.length == 1) {
        this.selected = (String) args[0]; // Server selected this protocol.
        return null;
      } else {
        return method.invoke(this, args);
      }
    }
  }

  /**
   * Concatenation of 8-bit, length prefixed protocol names.
   *
   * http://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04#page-4
   */
  static byte[] concatLengthPrefixed(List<Protocol> protocols) {
    int size = 0;
    for (Protocol protocol : protocols) {
      size += protocol.name.size() + 1; // add a byte for 8-bit length prefix.
    }
    byte[] result = new byte[size];
    int pos = 0;
    for (Protocol protocol : protocols) {
      int nameSize = protocol.name.size();
      result[pos++] = (byte) nameSize;
      // toByteArray allocates an array, but this is only called on new connections.
      System.arraycopy(protocol.name.toByteArray(), 0, result, pos, nameSize);
      pos += nameSize;
    }
    return result;
  }
}
