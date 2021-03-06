﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetToolBox.HashAuthentication.Abstractions;
using System;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace NetToolBox.HashAuthentication.AuthenticationHandler
{
    public sealed class HashCodeAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IHashCalculator _hashCalculator;

        public HashCodeAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IHashCalculator hashCalculator) : base(options, logger, encoder, clock)
        {
            _hashCalculator = hashCalculator;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var uri = new Uri(Request.GetDisplayUrl());
            Logger.LogInformation("Attempting to Validate {Url}", uri);
            if (_hashCalculator.IsValidUri(uri))
            {
                var identity = new ClaimsIdentity(Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            else
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid URL or HashCode"));
            }
        }
    }
}