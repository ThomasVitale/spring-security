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

import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the &quot;claims&quot; that can be returned in the Logout
 * Token, which provides information about the End-User authenticated Session to be terminated.
 *
 * @author Thomas Vitale
 * @since 5.6
 * @see ClaimAccessor
 * @see LogoutTokenClaimNames
 * @see OidcLogoutToken
 * @see <a target="_blank" href=
 *  * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout Token</a>
 */
public interface LogoutTokenClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Issuer identifier {@code (iss)}.
	 * @return the Issuer identifier
	 */
	default URL getIssuer() {
		return this.getClaimAsURL(LogoutTokenClaimNames.ISS);
	}

	/**
	 * Returns the Subject identifier {@code (sub)}.
	 * @return the Subject identifier
	 */
	default String getSubject() {
		return this.getClaimAsString(LogoutTokenClaimNames.SUB);
	}

	/**
	 * Returns the Audience(s) {@code (aud)} that this Logout Token is intended for.
	 * @return the Audience(s) that this Logout Token is intended for
	 */
	default List<String> getAudience() {
		return this.getClaimAsStringList(LogoutTokenClaimNames.AUD);
	}

	/**
	 * Returns the time at which the Logout Token was issued {@code (iat)}.
	 * @return the time at which the Logout Token was issued
	 */
	default Instant getIssuedAt() {
		return this.getClaimAsInstant(LogoutTokenClaimNames.IAT);
	}

	/**
	 * Returns a unique identifier for the Logout Token {@code (jti)}.
	 * @return the identifier for the Logout Token
	 */
	default String getTokenIdentifier() {
		return this.getClaimAsString(LogoutTokenClaimNames.JTI);
	}

	/**
	 * Returns the logout event represented by the JWT token {@code (events)}.
	 * @return the Back-Channel Logout event
	 */
	default Map<String, Object> getEvents() {
		return this.getClaimAsMap(LogoutTokenClaimNames.EVENTS);
	}

	/**
	 * Returns the identifier for the End-User authenticated Session {@code (sid)}.
	 * @return the Session identifier
	 */
	default String getSessionId() {
		return this.getClaimAsString(LogoutTokenClaimNames.SID);
	}
}
