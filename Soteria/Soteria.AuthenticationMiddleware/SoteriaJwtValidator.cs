using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace Soteria.AuthenticationMiddleware
{
    public class SoteriaJwtValidator : ISecurityTokenValidator
    {
        string _algorithm;
        TokenValidationParameters _validationParameters;
        public SoteriaJwtValidator(string algorithm, TokenValidationParameters validationParameters)
        {
            _algorithm = algorithm;
            _validationParameters = validationParameters;
        }
        public bool CanValidateToken
        {
            get { return true; }
        }

        public int MaximumTokenSizeInBytes { get { return 4000; } set => throw new NotImplementedException(); }

        public bool CanReadToken(string securityToken)
        {
            if (string.IsNullOrWhiteSpace(securityToken))
                return false;
            if (securityToken.Count(t => t == '.') == 3)
                return true;
            return false;
        }

        public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            var handler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = null;
            validatedToken = null;

            try
            {
                principal = handler.ValidateToken(securityToken, this._validationParameters, out validatedToken);

                var validJwt = validatedToken as JwtSecurityToken;

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
            return principal;
        }
    }
}
