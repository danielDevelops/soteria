using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    public interface ISessionHandler
    {
        bool EnableSessionValidation { get; }
        TimeSpan SessionRecheck { get; }
        Task DeleteSessionAsync(Guid sessionGuid);
        Task<bool> IsSessionActiveAsync(Guid sessionGuid);
    }
}
