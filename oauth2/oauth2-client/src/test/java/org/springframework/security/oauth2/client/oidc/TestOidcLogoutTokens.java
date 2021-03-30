/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.client.oidc;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;

import org.springframework.security.oauth2.core.oidc.OidcLogoutToken;

/**
 * @author Thomas Vitale
 * @since 5.6
 */
public class TestOidcLogoutTokens {

	private TestOidcLogoutTokens() {
	}

	public static OidcLogoutToken withSub() {
		return OidcLogoutToken.withTokenValue("logout-token")
				.issuer("https://example.com")
				.subject("subject")
				.audience(Collections.unmodifiableSet(new LinkedHashSet<>(Collections.singletonList("client"))))
				.issuedAt(Instant.now())
				.tokenIdentifier("jti")
				.build();
	}

	public static OidcLogoutToken withSid() {
		return OidcLogoutToken.withTokenValue("logout-token")
				.issuer("https://example.com")
				.audience(Collections.unmodifiableSet(new LinkedHashSet<>(Collections.singletonList("client"))))
				.issuedAt(Instant.now())
				.tokenIdentifier("jti")
				.sessionId("session-id")
				.build();
	}

	public static OidcLogoutToken complete() {
		return OidcLogoutToken.withTokenValue("logout-token")
				.issuer("https://example.com")
				.subject("subject")
				.audience(Collections.unmodifiableSet(new LinkedHashSet<>(Collections.singletonList("client"))))
				.issuedAt(Instant.now())
				.tokenIdentifier("jti")
				.sessionId("session-id")
				.build();
	}
}
