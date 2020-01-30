using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    public interface IPermissionHandler
    {
        Task<List<string>> GetPermission(string user);
        TimeSpan PermissionsTimeout { get; }
    }
}
