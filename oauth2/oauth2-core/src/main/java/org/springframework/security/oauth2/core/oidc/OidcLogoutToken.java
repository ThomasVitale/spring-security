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

package org.springframework.security.oauth2.core.oidc;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing an OpenID Connect
 * Back-Channel Logout 1.0 Logout Token.
 *
 * <p>
 * The {@code OidcLogoutToken} is a Security Event Token (SET) that contains
 * &quot;claims&quot; about the End-User authenticated session to be terminated.
 *
 * @author Thomas Vitale
 * @since 5.6
 * @see AbstractOAuth2Token
 * @see LogoutTokenClaimAccessor
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout Token</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc8417">Security Event Token (SET)</a>
 */
public class OidcLogoutToken extends AbstractOAuth2Token implements LogoutTokenClaimAccessor {

	public static final String BACKCHANNEL_LOGOUT_SCHEMA = "http://schemas.openid.net/event/backchannel-logout";
	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code OidcLogoutToken} using the provided parameters.
	 * @param tokenValue the Logout Token value
	 * @param issuedAt the time at which the Logout Token was issued {@code (iat)}
	 * @param claims the claims about the logout event for the End-User authentication
	 */
	public OidcLogoutToken(String tokenValue, Instant issuedAt, Map<String, Object> claims) {
		super(tokenValue, issuedAt, null);
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Create a {@link Builder} based on the given token value
	 * @param tokenValue the token value to use
	 * @return the {@link Builder} for further configuration
	 */
	public static Builder withTokenValue(String tokenValue) {
		return new Builder(tokenValue);
	}

	/**
	 * A builder for {@link OidcLogoutToken}s
	 */
	public static final class Builder {

		private String tokenValue;

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		/**
		 * Use this token value in the resulting {@link OidcLogoutToken}
		 * @param tokenValue The token value to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenValue(String tokenValue) {
			this.tokenValue = tokenValue;
			return this;
		}

		/**
		 * Use this claim in the resulting {@link OidcLogoutToken}
		 * @param name The claim name
		 * @param value The claim value
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param claimsConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Use this audience in the resulting {@link OidcLogoutToken}
		 * @param audience The audience(s) to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder audience(Collection<String> audience) {
			return claim(LogoutTokenClaimNames.AUD, audience);
		}

		/**
		 * Use this issued-at timestamp in the resulting {@link OidcLogoutToken}
		 * @param issuedAt The issued-at timestamp to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuedAt(Instant issuedAt) {
			return this.claim(LogoutTokenClaimNames.IAT, issuedAt);
		}

		/**
		 * Use this issuer in the resulting {@link OidcLogoutToken}
		 * @param issuer The issuer to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuer(String issuer) {
			return this.claim(LogoutTokenClaimNames.ISS, issuer);
		}

		/**
		 * Use this sessionId in the resulting {@link OidcLogoutToken}
		 * @param sessionId The session identifier to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder sessionId(String sessionId) {
			return this.claim(LogoutTokenClaimNames.SID, sessionId);
		}

		/**
		 * Use this subject in the resulting {@link OidcLogoutToken}
		 * @param subject The subject to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			return this.claim(LogoutTokenClaimNames.SUB, subject);
		}

		/**
		 * Use this unique identifier in the resulting {@link OidcLogoutToken}
		 * @param tokenIdentifier The token identifier to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenIdentifier(String tokenIdentifier) {
			return this.claim(LogoutTokenClaimNames.JTI, tokenIdentifier);
		}

		/**
		 * Build the {@link OidcLogoutToken}
		 * @return The constructed {@link OidcLogoutToken}
		 */
		public OidcLogoutToken build() {
			this.claim(LogoutTokenClaimNames.EVENTS, getLogoutEvents());
			Instant iat = toInstant(this.claims.get(LogoutTokenClaimNames.IAT));
			return new OidcLogoutToken(this.tokenValue, iat, this.claims);
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp != null) {
				Assert.isInstanceOf(Instant.class, timestamp, "timestamps must be of type Instant");
			}
			return (Instant) timestamp;
		}

		private Map<String, Object> getLogoutEvents() {
			Map<String, Object> events = new HashMap<>();
			events.put(BACKCHANNEL_LOGOUT_SCHEMA, new HashMap<>());
			return events;
		}
	}
}
