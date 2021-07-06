using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware.UserInformation
{
    public class UserService<T> where T : class, new()
    {
        private readonly HttpContext context;
        private readonly SessionManager sessionManager;

        public SoteriaUser<T> GetUser()
            => new SoteriaUser<T>(context.User, 
                context, 
                sessionManager.sessionHandler);

        public async Task<bool> IsUserInRole(string role)
            => await (GetUser()).IsInRoleAsync(role);

        public UserService(IHttpContextAccessor context, ISessionHandler sessionHandler)
        {
            this.context = context.HttpContext;
            this.sessionManager =  new SessionManager(sessionHandler);
        }

        public UserService(HttpContext context, ISessionHandler sessionHandler)
        {
            this.context = context;
            this.sessionManager = new SessionManager(sessionHandler);
        }
    }
}
