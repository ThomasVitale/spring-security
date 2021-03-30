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

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.LogoutTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.security.oauth2.core.oidc.OidcLogoutToken.BACKCHANNEL_LOGOUT_SCHEMA;

/**
 * Tests for {@link OidcLogoutTokenValidator}.
 *
 * @author Thomas Vitale
 */
public class OidcLogoutTokenValidatorTests {

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration();

	private final Map<String, Object> headers = new HashMap<>();
	private final Map<String, Object> claims = new HashMap<>();
	private final Instant issuedAt = Instant.now();
	private final Duration clockSkew = Duration.ofSeconds(60);

	@Before
	public void setup() {
		this.headers.put("alg", JwsAlgorithms.RS256);
		this.claims.put(LogoutTokenClaimNames.ISS, "https://example.com");
		this.claims.put(LogoutTokenClaimNames.SUB, "subject");
		this.claims.put(LogoutTokenClaimNames.AUD, Collections.singletonList("client-id"));
		this.claims.put(LogoutTokenClaimNames.IAT, issuedAt);
		this.claims.put(LogoutTokenClaimNames.JTI, "jit");
		this.claims.put(LogoutTokenClaimNames.EVENTS, getLogoutEvents());
		this.claims.put(LogoutTokenClaimNames.SID, "session-id");
	}

	@Test
	public void validateWhenValidThenNoErrors() {
		assertThat(this.validateLogoutToken()).isEmpty();
	}

	@Test
	public void setClockSkewWhenNullThenThrowIllegalArgumentException() {
		OidcLogoutTokenValidator logoutTokenValidator = new OidcLogoutTokenValidator(this.registration.build());
		assertThatIllegalArgumentException()
				.isThrownBy(() -> logoutTokenValidator.setClockSkew(null));
	}

	@Test
	public void setClockSkewWhenNegativeSecondsThenThrowIllegalArgumentException() {
		OidcLogoutTokenValidator logoutTokenValidator = new OidcLogoutTokenValidator(this.registration.build());
		assertThatIllegalArgumentException()
				.isThrownBy(() -> logoutTokenValidator.setClockSkew(Duration.ofSeconds(-1)));
	}

	@Test
	public void setClockWhenNullThenThrowIllegalArgumentException() {
		OidcLogoutTokenValidator logoutTokenValidator = new OidcLogoutTokenValidator(this.registration.build());
		assertThatIllegalArgumentException()
				.isThrownBy(() -> logoutTokenValidator.setClock(null));
	}

	@Test
	public void validateWhenIssuerNullThenHasErrors() {
		this.claims.remove(LogoutTokenClaimNames.ISS);
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.ISS));
	}

	@Test
	public void validateWhenMetadataIssuerMatchThenNoErrors() {
		this.registration = this.registration.issuerUri("https://example.com");
		assertThat(this.validateLogoutToken()).isEmpty();
	}

	@Test
	public void validateWhenMetadataIssuerMismatchThenHasErrors() {
		this.registration = this.registration.issuerUri("https://anotherissuer.com");
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.ISS));
	}

	@Test
	public void validateWhenSubAndNoSidThenNoErrors() {
		this.claims.remove(LogoutTokenClaimNames.SID);
		assertThat(this.validateLogoutToken()).isEmpty();
	}

	@Test
	public void validateWhenSidAndNoSubThenNoErrors() {
		this.claims.remove(LogoutTokenClaimNames.SUB);
		assertThat(this.validateLogoutToken()).isEmpty();
	}

	@Test
	public void validateWhenSubAndSidNullThenHasErrors() {
		this.claims.remove(LogoutTokenClaimNames.SUB);
		this.claims.remove(LogoutTokenClaimNames.SID);
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.anyMatch((error) -> error.getDescription().contains(LogoutTokenClaimNames.SUB))
				.anyMatch((error) -> error.getDescription().contains(LogoutTokenClaimNames.SID));
	}

	@Test
	public void validateWhenMultipleAudThenNoErrors() {
		this.claims.put(IdTokenClaimNames.AUD, Arrays.asList("client-id", "another-client-id"));
		assertThat(this.validateLogoutToken()).isEmpty();
	}

	@Test
	public void validateWhenAudNullThenHasErrors() {
		this.claims.remove(LogoutTokenClaimNames.AUD);
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.AUD));
	}

	@Test
	public void validateWhenIssuedAtNullThenHasErrors() {
		this.claims.remove(LogoutTokenClaimNames.IAT);
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.IAT));
	}

	@Test
	public void validateWhenJtiNullThenHasErrors() {
		this.claims.remove(LogoutTokenClaimNames.JTI);
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.JTI));
	}

	@Test
	public void validateWhenNOnceThenHasErrors() {
		this.claims.put("nonce", "1234567890");
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains("nonce"));
	}

	@Test
	public void validateFormatError() {
		this.claims.remove(LogoutTokenClaimNames.SUB);
		this.claims.remove(LogoutTokenClaimNames.SID);
		assertThat(this.validateLogoutToken())
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.equals("The Logout Token contains invalid claims: {sub=null, sid=null}"));
	}

	@Test
	public void validateWhenIdTokenIssuerMatchThenNoErrors() {
		OidcIdToken idToken = generateIdToken();
		assertThat(this.validateLogoutToken(idToken)).isEmpty();
	}

	@Test
	public void validateWhenIdTokenIssuerMismatchThenHasErrors() {
		OidcIdToken idToken = generateIdToken();
		this.claims.put(LogoutTokenClaimNames.ISS, "https://anotherissuer.com");
		assertThat(this.validateLogoutToken(idToken))
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.ISS));
	}

	@Test
	public void validateWhenIdTokenSubjectMatchThenNoErrors() {
		OidcIdToken idToken = generateIdToken();
		assertThat(this.validateLogoutToken(idToken)).isEmpty();
	}

	@Test
	public void validateWhenIdTokenSubjectMismatchThenHasErrors() {
		OidcIdToken idToken = generateIdToken();
		this.claims.put(LogoutTokenClaimNames.SUB, "anotherSubject");
		assertThat(this.validateLogoutToken(idToken))
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.SUB));
	}

	@Test
	public void validateWhenIdTokenSessionIdMatchThenNoErrors() {
		OidcIdToken idToken = generateIdToken();
		assertThat(this.validateLogoutToken(idToken)).isEmpty();
	}

	@Test
	public void validateWhenIdTokenSessionIdMismatchThenHasErrors() {
		OidcIdToken idToken = generateIdToken();
		this.claims.put(LogoutTokenClaimNames.SID, "anotherSessionId");
		assertThat(this.validateLogoutToken(idToken))
				.hasSize(1)
				.extracting(OAuth2Error::getDescription)
				.allMatch((msg) -> msg.contains(LogoutTokenClaimNames.SID));
	}

	private Collection<OAuth2Error> validateLogoutToken() {
		return validateLogoutToken(null);
	}

	private Collection<OAuth2Error> validateLogoutToken(OidcIdToken idToken) {
		Jwt logoutToken = Jwt.withTokenValue("token")
				.headers((h) -> h.putAll(this.headers))
				.claims((c) -> c.putAll(this.claims))
				.build();
		OidcLogoutTokenValidator validator = new OidcLogoutTokenValidator(this.registration.build(), idToken);
		validator.setClockSkew(this.clockSkew);
		return validator.validate(logoutToken).getErrors();
	}

	private Map<String, Object> getLogoutEvents() {
		Map<String, Object> events = new HashMap<>();
		events.put(BACKCHANNEL_LOGOUT_SCHEMA, new HashMap<>());
		return events;
	}

	public OidcIdToken generateIdToken() {
		return OidcIdToken.withTokenValue("id-token")
				.issuer("https://example.com")
				.subject("subject")
				.audience(Collections.singletonList("client-id"))
				.issuedAt(Instant.now())
				.sessionId("session-id")
				.build();
	}
}
