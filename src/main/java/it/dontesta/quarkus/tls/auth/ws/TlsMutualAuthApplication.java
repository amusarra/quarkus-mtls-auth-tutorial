/*
 * Copyright (c) 2024 Antonio Musarra's Blog.
 * SPDX-License-Identifier: MIT
 */

package it.dontesta.quarkus.tls.auth.ws;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

/**
 * JAX-RS Application class that defines the base URI for the RESTful web services.
 *
 * <p><a href="https://jakarta.ee/specifications/restful-ws/3.1/jakarta-restful-ws-spec-3.1.html#application">JAX-RS Application</a>
 *
 * @author Antonio Musarra
 */
@ApplicationPath("/api")
public class TlsMutualAuthApplication extends Application {
}
