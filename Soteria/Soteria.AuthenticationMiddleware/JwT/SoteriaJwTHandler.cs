using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
namespace Soteria.AuthenticationMiddleware
{
    internal sealed class SoteriaJwTHandler : JwtBearerHandler
    {
        public SoteriaJwTHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDataProtectionProvider dataProtection, ISystemClock clock)
            : base(options, logger, encoder, dataProtection, clock)
        {
        }
        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Exception = new Exception("You are not authorized to access this resource.")
            };
            return Events.AuthenticationFailed(authenticationFailedContext);
        }
    }
}
