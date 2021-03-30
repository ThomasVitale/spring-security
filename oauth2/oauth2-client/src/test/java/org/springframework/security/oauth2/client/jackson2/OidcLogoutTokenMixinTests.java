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

package org.springframework.security.oauth2.client.jackson2;

import java.time.Instant;
import java.util.HashMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.DecimalUtils;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.oidc.TestOidcLogoutTokens;
import org.springframework.security.oauth2.core.oidc.OidcLogoutToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OidcLogoutTokenMixin}.
 *
 * @author Thomas Vitale
 */
public class OidcLogoutTokenMixinTests {

	private ObjectMapper mapper;

	@Before
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));

		// see https://github.com/FasterXML/jackson-databind/issues/3052 for details
		this.mapper.configure(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS, true);
	}

	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.complete();
		String expectedJson = asJson(logoutToken);
		String json = this.mapper.writeValueAsString(logoutToken);
		System.out.println(json);
		System.out.println(expectedJson);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		OidcLogoutToken expectedLogoutToken = TestOidcLogoutTokens.complete();
		String json = asJson(expectedLogoutToken);
		assertThatExceptionOfType(JsonProcessingException.class)
				.isThrownBy(() -> new ObjectMapper().readValue(json, OidcLogoutToken.class));
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		OidcLogoutToken expectedLogoutToken = TestOidcLogoutTokens.complete();
		String json = asJson(expectedLogoutToken);
		OidcLogoutToken logoutToken = this.mapper.readValue(json, OidcLogoutToken.class);
		assertThat(logoutToken.getIssuer()).isEqualTo(expectedLogoutToken.getIssuer());
		assertThat(logoutToken.getSubject()).isEqualTo(expectedLogoutToken.getSubject());
		assertThat(logoutToken.getAudience()).containsExactlyElementsOf(expectedLogoutToken.getAudience());
		assertThat(logoutToken.getIssuedAt()).isEqualTo(expectedLogoutToken.getIssuedAt());
		assertThat(logoutToken.getTokenIdentifier()).isEqualTo(expectedLogoutToken.getTokenIdentifier());
		assertThat(logoutToken.getEvents()).containsEntry(OidcLogoutToken.BACKCHANNEL_LOGOUT_SCHEMA, new HashMap<>());
		assertThat(logoutToken.getSessionId()).isEqualTo(expectedLogoutToken.getSessionId());
	}

	private static String asJson(OidcLogoutToken logoutToken) {
		// @formatter:off
		return "{"
				+ "\"@class\":\"org.springframework.security.oauth2.core.oidc.OidcLogoutToken\","
				+ "\"tokenValue\":\"logout-token\","
				+ "\"issuedAt\":" + toString(logoutToken.getIssuedAt()) + ","
				+ "\"claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\","
					+ "\"iss\":\"" + logoutToken.getIssuer().toString() + "\","
					+ "\"sub\":\"" + logoutToken.getSubject() + "\","
					+ "\"aud\":[\"java.util.Collections$UnmodifiableSet\",[\"" + logoutToken.getAudience().get(0) + "\"]],"
					+ "\"iat\":[\"java.time.Instant\"," + toString(logoutToken.getIssuedAt()) + "],"
					+ "\"jti\":\"" + logoutToken.getTokenIdentifier() + "\","
					+ "\"sid\":\"" + logoutToken.getSessionId() + "\","
					+ "\"events\":{\"@class\":\"java.util.HashMap\",\"" + OidcLogoutToken.BACKCHANNEL_LOGOUT_SCHEMA + "\":{\"@class\":\"java.util.HashMap\"}}"
				+ "},"
				+ "\"expiresAt\":null}\n";
		// @formatter:on
	}

	private static String toString(Instant instant) {
		if (instant == null) {
			return null;
		}
		return DecimalUtils.toBigDecimal(instant.getEpochSecond(), instant.getNano()).toString();
	}
}
