using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

namespace Soteria.AuthenticationMiddleware
{
    public class SoteriaJwtDataFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string _algorithm;
        private readonly TokenValidationParameters _validationParameters;

        public SoteriaJwtDataFormat(string algorithm, TokenValidationParameters validationParameters)
        {
            this._algorithm = algorithm;
            this._validationParameters = validationParameters;
        }

        public AuthenticationTicket Unprotect(string protectedText)
            => Unprotect(protectedText, null);

        public AuthenticationTicket Unprotect(string protectedText, string purpose)
        {
            var handler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = null;
            SecurityToken validToken = null;

            try
            {
                principal = handler.ValidateToken(protectedText, this._validationParameters, out validToken);

                var validJwt = validToken as JwtSecurityToken;

                if (validJwt == null)
                {
                    throw new ArgumentException("Invalid JWT");
                }

                if (!validJwt.Header.Alg.Equals(_algorithm, StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Algorithm must be '{_algorithm}'");
                }

            }
            catch (SecurityTokenValidationException x)
            {
                return null;
            }
            catch (ArgumentException x)
            {
                return null;
            }

            // Token validation passed
            return new AuthenticationTicket(principal, new Microsoft.AspNetCore.Authentication.AuthenticationProperties(), $"{AuthManager.MiddleWareInstanceName}-jwt");
        }

        public string Protect(AuthenticationTicket data) => Protect(data, null);

        public string Protect(AuthenticationTicket data, string purpose)
        {
            if (data == null)
                throw new NullReferenceException("AuthenticationTicket cannot be null");
            return CreateJWT(data.Principal.Claims, data.Properties.IssuedUtc, data.Properties.ExpiresUtc);
        }

        public string CreateJWT(IEnumerable<Claim> claims, DateTimeOffset? issued, DateTimeOffset? expires)
        {
            string audienceId = _validationParameters.ValidAudience;

            var signingKey = new SigningCredentials(_validationParameters.IssuerSigningKey, _algorithm);
            
            var token = new JwtSecurityToken(
                _validationParameters.ValidIssuer, audienceId, claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingKey);

            var handler = new JwtSecurityTokenHandler();

            var jwt = handler.WriteToken(token);

            return jwt;
        }
    }
}
