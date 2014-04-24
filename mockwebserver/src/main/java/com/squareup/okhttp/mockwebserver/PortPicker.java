/*
 * Copyright (C) 2014 Square, Inc.
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
package com.squareup.okhttp.mockwebserver;

import java.net.ServerSocket;
import java.util.concurrent.atomic.AtomicInteger;

/** Utility class that helps us pick an available IP port. */
public class PortPicker {

  private PortPicker() {
  }

  private static final int MAX_PORT = 2048;
  private static final AtomicInteger lastPort = new AtomicInteger(1024);

  /** Returns an available IP port or throws a {@linkplain RuntimeException}. */
  public static int pickPort() {
    int port;
    while ((port = lastPort.incrementAndGet()) < MAX_PORT) {
      if (isPortAvailable(port)) {
        return port;
      }
    }
    throw new RuntimeException("Failed to find a free port");
  }

  private static boolean isPortAvailable(int port) {
    ServerSocket socket = null;
    try {
      try {
        socket = new ServerSocket(port);
        return true;
      } finally {
        if (socket != null) {
          socket.close();
        }
      }
    } catch (Exception ignored) {
    }
    return false;
  }
}
