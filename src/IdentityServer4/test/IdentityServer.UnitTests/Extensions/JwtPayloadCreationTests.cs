using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using IdentityModel;
using IdentityServer.UnitTests.Common;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Xunit;

namespace IdentityServer.UnitTests.Extensions
{
    public class JwtPayloadCreationTests
    {
        private Token _token;

        public JwtPayloadCreationTests()
        {
            var jsonArraySingle = JsonSerializer.Serialize(new[] { "A", "B", "C" });
            var jsonArrayMulti1 = JsonSerializer.Serialize(new[] { 1, 2, 3 });
            var jsonArrayMulti2 = JsonSerializer.Serialize(new[] { "D", "E", "F" });

            var jsonObjectSingle = JsonSerializer.Serialize(new { sprop = "SP1 value" });
            var jsonObjectMulti1 = JsonSerializer.Serialize(new { mprop = "MP1 1 value" });
            var jsonObjectMulti2 = JsonSerializer.Serialize(new { mprop = "MP2 2 value" });


            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Scope, "scope1"),
                new Claim(JwtClaimTypes.Scope, "scope2"),
                new Claim(JwtClaimTypes.Scope, "scope3"),
                new Claim("JsonArraySingle",jsonArraySingle, IdentityServerConstants.ClaimValueTypes.Json),
                new Claim("JsonArrayMulti",jsonArrayMulti1, IdentityServerConstants.ClaimValueTypes.Json),
                new Claim("JsonArrayMulti",jsonArrayMulti2, IdentityServerConstants.ClaimValueTypes.Json),
                new Claim("JsonObjectSingle",jsonObjectSingle, IdentityServerConstants.ClaimValueTypes.Json),
                new Claim("JsonObjectMulti",jsonObjectMulti1, IdentityServerConstants.ClaimValueTypes.Json),
                new Claim("JsonObjectMulti",jsonObjectMulti2, IdentityServerConstants.ClaimValueTypes.Json),
            };

            _token = new Token(OidcConstants.TokenTypes.AccessToken)
            {
                CreationTime = DateTime.UtcNow,
                Issuer = "issuer",
                Lifetime = 60,
                Claims = claims.Distinct(new ClaimComparer()).ToList(),
                ClientId = "client"
            };
        }

        [Fact]
        public void Should_create_scopes_as_array_by_default()
        {
            var options = new IdentityServerOptions();
            var payload = _token.CreateJwtPayload(new SystemClock(), options, TestLogger.Create<JwtPayloadCreationTests>());

            payload.Should().NotBeNull();
            var scopes = payload.Claims.Where(c => c.Type == JwtClaimTypes.Scope).ToArray();
            scopes.Count().Should().Be(3);
            scopes[0].Value.Should().Be("scope1");
            scopes[1].Value.Should().Be("scope2");
            scopes[2].Value.Should().Be("scope3");
        }

        [Fact]
        public void Should_create_scopes_as_string()
        {
            var options = new IdentityServerOptions
            {
                EmitScopesAsSpaceDelimitedStringInJwt = true
            };

            var payload = _token.CreateJwtPayload(new SystemClock(), options, TestLogger.Create<JwtPayloadCreationTests>());

            payload.Should().NotBeNull();
            var scopes = payload.Claims.Where(c => c.Type == JwtClaimTypes.Scope).ToList();
            scopes.Count().Should().Be(1);
            scopes.First().Value.Should().Be("scope1 scope2 scope3");
        }

        [Fact]
        public void Should_create_valid_claim_with_json_array()
        {
            var options = new IdentityServerOptions
            {
                EmitScopesAsSpaceDelimitedStringInJwt = true
            };

            var payload = _token.CreateJwtPayload(new SystemClock(), options, TestLogger.Create<JwtPayloadCreationTests>());

            payload.Should().NotBeNull();

            payload["JsonObjectSingle"].Should().NotBeNull();
        }
    }
}
