using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    internal static class Extensions
    {
        public static string EnsureNullIsEmpty(this string value)
        {
            if (value == null)
                return string.Empty;
            return value;
        }
        public static bool IsAjaxRequest(this HttpRequest request)
        {
            if (request.Headers["x-requested-with"] == "XMLHttpRequest")
                return true;
            if (request.Headers["Accept"].ToString().Contains("application/json"))
                return true;
            return false;
        }

        public static ClaimsIdentity GetSoteriaIdentity(this ClaimsPrincipal claimsPrincipal)
        {
            return claimsPrincipal.Identities?.SingleOrDefault(t => 
                t.AuthenticationType == $"{AuthManager.MiddleWareInstanceName}-jwt"
                || t.AuthenticationType == AuthManager.MiddleWareInstanceName);
        }

        public static SessionManager GetSessionManager(this HttpContext httpContext)
        {
            var services = httpContext.RequestServices;
            var sessionHandler = (ISessionHandler)services.GetService(typeof(ISessionHandler));
            return new SessionManager(sessionHandler);
        }
    }
    
}
