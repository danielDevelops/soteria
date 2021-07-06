using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware.UserInformation
{
    public interface ISoteriaUserValidation
    {
        string ClaimID { get; }
        bool ValidClaimInformation { get; }
        ClaimsIdentity Identity { get; }
        Task<bool> IsAuthenticatedAsync();
        Task<bool> IsInRoleAsync(string role);
    }
}
