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

package org.springframework.security.oauth2.client.oidc.logout;

import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.LogoutTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcLogoutToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * An {@link OAuth2TokenValidator} responsible for validating the claims in an
 * {@link OidcLogoutToken Logout Token}.
 *
 * @author Thomas Vitale
 * @since 5.6
 * @see OAuth2TokenValidator
 * @see Jwt
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation">Logout Token
 * Validation</a>
 */
public final class OidcLogoutTokenValidator implements OAuth2TokenValidator<Jwt> {

	private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

	private final ClientRegistration clientRegistration;

	private final OidcIdToken idToken;

	private Duration clockSkew = DEFAULT_CLOCK_SKEW;

	private Clock clock = Clock.systemUTC();

	public OidcLogoutTokenValidator(ClientRegistration clientRegistration) {
		this(clientRegistration, null);
	}

	public OidcLogoutTokenValidator(ClientRegistration clientRegistration, OidcIdToken idToken) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.clientRegistration = clientRegistration;
		this.idToken = idToken;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt logoutToken) {
		// 2.6 Logout Token Validation
		// https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
		Map<String, Object> invalidClaims = validateRequiredClaims(logoutToken);
		if (!invalidClaims.isEmpty()) {
			return OAuth2TokenValidatorResult.failure(invalidLogoutToken(invalidClaims));
		}

		// 3. Validate the iss, aud, and iat Claims in the same way they are validated in ID Tokens.
		String metadataIssuer = this.clientRegistration.getProviderDetails().getIssuerUri();
		if (metadataIssuer != null && !Objects.equals(metadataIssuer, logoutToken.getIssuer().toExternalForm())) {
			invalidClaims.put(LogoutTokenClaimNames.ISS, logoutToken.getIssuer());
		}
		if (!logoutToken.getAudience().contains(this.clientRegistration.getClientId())) {
			invalidClaims.put(LogoutTokenClaimNames.AUD, logoutToken.getAudience());
		}
		Instant now = Instant.now(this.clock);
		Instant issuedAt = logoutToken.getIssuedAt();
		if (issuedAt == null || now.plus(this.clockSkew).isBefore(issuedAt)) {
			invalidClaims.put(LogoutTokenClaimNames.IAT, logoutToken.getIssuedAt());
		}

		// 4. Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
		String subject = logoutToken.getSubject();
		String sessionId = logoutToken.getClaimAsString(LogoutTokenClaimNames.SID);
		if (subject == null && sessionId == null) {
			invalidClaims.put(LogoutTokenClaimNames.SUB, subject);
			invalidClaims.put(LogoutTokenClaimNames.SID, sessionId);
		}

		// 5. Verify that the Logout Token contains an events Claim whose value is JSON object containing
		// the member name http://schemas.openid.net/event/backchannel-logout.
		Map<String,Object> events = logoutToken.getClaimAsMap(LogoutTokenClaimNames.EVENTS);
		if (events.get(OidcLogoutToken.BACKCHANNEL_LOGOUT_SCHEMA) == null) {
			invalidClaims.put(LogoutTokenClaimNames.EVENTS, events);
		}

		// 6. Verify that the Logout Token does not contain a nonce Claim.
		String nonce = logoutToken.getClaimAsString("nonce");
		if (nonce != null) {
			invalidClaims.put("nonce", nonce);
		}

		// 7. Optionally verify that another Logout Token with the same jti value
		// has not been recently received.
		// TODO thv Do we want a logout token repository?

		// 8. Optionally verify that the iss Logout Token Claim matches the iss Claim in an ID Token issued
		// for the current session or a recent session of this RP with the OP.
		// TODO thv What about the "recent session" part?
		String issuer = logoutToken.getIssuer().toString();
		if (idToken != null && !issuer.equals(idToken.getIssuer().toString())) {
			invalidClaims.put(LogoutTokenClaimNames.ISS, issuer);
		}

		// 9. Optionally verify that any sub Logout Token Claim matches the sub Claim in an ID Token issued
		// for the current session or a recent session of this RP with the OP.
		if (idToken != null && subject != null && !subject.equals(idToken.getSubject())) {
			invalidClaims.put(LogoutTokenClaimNames.SUB, subject);
		}

		// 10. Optionally verify that any sid Logout Token Claim matches the sid Claim in an ID Token issued
		// for the current session or a recent session of this RP with the OP.
		if (idToken != null && sessionId != null && !sessionId.equals(idToken.getSessionId())) {
			invalidClaims.put(LogoutTokenClaimNames.SID, sessionId);
		}

		if (!invalidClaims.isEmpty()) {
			return OAuth2TokenValidatorResult.failure(invalidLogoutToken(invalidClaims));
		}

		return OAuth2TokenValidatorResult.success();
	}

	/**
	 * Sets the maximum acceptable clock skew. The default is 60 seconds. The clock skew
	 * is used when validating the {@link JwtClaimNames#EXP exp} and
	 * {@link JwtClaimNames#IAT iat} claims.
	 * @param clockSkew the maximum acceptable clock skew
	 * @since 5.2
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when validating the
	 * {@link JwtClaimNames#EXP exp} and {@link JwtClaimNames#IAT iat} claims.
	 * @param clock the clock
	 * @since 5.3
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	private static OAuth2Error invalidLogoutToken(Map<String, Object> invalidClaims) {
		return new OAuth2Error("invalid_logout_token", "The Logout Token contains invalid claims: " + invalidClaims,
				"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
	}

	private static Map<String, Object> validateRequiredClaims(Jwt logoutToken) {
		Map<String, Object> requiredClaims = new HashMap<>();
		URL issuer = logoutToken.getIssuer();
		if (issuer == null) {
			requiredClaims.put(LogoutTokenClaimNames.ISS, issuer);
		}
		List<String> audience = logoutToken.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			requiredClaims.put(LogoutTokenClaimNames.AUD, audience);
		}
		Instant issuedAt = logoutToken.getIssuedAt();
		if (issuedAt == null) {
			requiredClaims.put(LogoutTokenClaimNames.IAT, issuedAt);
		}
		String tokenIdentifier = logoutToken.getClaimAsString(LogoutTokenClaimNames.JTI);
		if (tokenIdentifier == null) {
			requiredClaims.put(LogoutTokenClaimNames.JTI, tokenIdentifier);
		}
		Map<String,Object> events = logoutToken.getClaimAsMap(LogoutTokenClaimNames.EVENTS);
		if (CollectionUtils.isEmpty(events)) {
			requiredClaims.put(LogoutTokenClaimNames.EVENTS, events);
		}
		return requiredClaims;
	}
}
