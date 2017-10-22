using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Soteria.AuthenticationMiddleware.UserInformation
{
    public interface ISoteriaUserValidation
    {
        string ClaimID { get; }
        bool ValidClaimInformation { get; }
        ClaimsIdentity Identity { get; }
        bool IsAuthenticated { get; }
        bool IsInRole(HttpContext context, string role);
    }
}
