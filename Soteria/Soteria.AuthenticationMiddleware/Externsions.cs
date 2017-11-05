using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
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
    }
    
}
