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
        
        private readonly IHttpContextAccessor _context;
        public SoteriaUser<T> User { get; private set; }
        public bool IsUserInRole(string role)
        {
            return User.IsInRole(_context.HttpContext, role);
        }
        public UserService(IHttpContextAccessor context)
        {
            _context = context;
            User = new SoteriaUser<T>(_context.HttpContext.User, _context.HttpContext);
        }
    }
}
