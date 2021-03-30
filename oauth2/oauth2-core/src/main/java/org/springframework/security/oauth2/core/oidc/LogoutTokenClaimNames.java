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

/**
 * The names of the &quot;claims&quot; defined by the OpenID Connect Back-Channel Logout 1.0
 * and OpenID Connect Core 1.0 specifications that can be returned in the Logout Token.
 *
 * @author Thomas Vitale
 * @since 5.6
 * @see OidcLogoutToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout Token</a>
 */
public interface LogoutTokenClaimNames {

	/**
	 * {@code iss} - the Issuer identifier
	 */
	String ISS = "iss";

	/**
	 * {@code sub} - the Subject identifier
	 */
	String SUB = "sub";

	/**
	 * {@code aud} - the Audience(s) that the Logout Token is intended for
	 */
	String AUD = "aud";

	/**
	 * {@code iat} - the time at which the Logout Token was issued
	 */
	String IAT = "iat";

	/**
	 * {@code jti} - unique identifier for the Logout Token
	 */
	String JTI = "jti";

	/**
	 * {@code events} - declares that the JWT is a Logout Token
	 */
	String EVENTS = "events";

	/**
	 * {@code azp} - identifier for an End-User authenticated Session
	 */
	String SID = "sid";
}
