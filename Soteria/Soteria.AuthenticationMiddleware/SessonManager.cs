using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    internal class SessionManager
    {
        static readonly ConcurrentDictionary<Guid, DateTime> sessions = new ConcurrentDictionary<Guid, DateTime>();
        private readonly ISessionHandler sessionHandler;

        public SessionManager(ISessionHandler sessionHandler)
        {
            this.sessionHandler = sessionHandler;
        }

        public async Task<bool> IsSessionActiveAsync(Guid sessionGuid)
        {
            if (!sessionHandler.EnableSessionValidation)
                return true;
            if (sessionGuid == Guid.Empty)
                return false;
            if (sessions.TryGetValue(sessionGuid, out var currentSessionTimestamp) 
                && (DateTime.Now - currentSessionTimestamp) < sessionHandler.SessionRecheck)
            {
                sessions.TryUpdate(sessionGuid, DateTime.Now, DateTime.Now);
                return true;
            }

            var isStillValid = await sessionHandler.IsSessionActiveAsync(sessionGuid);
            if (!isStillValid)
                return false;
            sessions.AddOrUpdate(sessionGuid, DateTime.Now, (Guid key, DateTime timestamp) => DateTime.Now);
            return true;
        }

        public async Task<bool> IsSessionActiveAsync(HttpContext httpContext)
        {
            var sessionGuid = httpContext?.User?.GetSoteriaIdentity()?.FindFirst("SessionGuid")?.Value;
            if (string.IsNullOrWhiteSpace(sessionGuid))
                return false;
            return await IsSessionActiveAsync(new Guid(sessionGuid));
        }

        public void AddNewSession(Guid sessionGuid)
        {
            sessions.AddOrUpdate(sessionGuid, DateTime.Now, (Guid key, DateTime timestamp) => DateTime.Now);
        }

        public static void RemoveGuid(Guid sessionGuid)
        {
            if (sessionGuid == Guid.Empty)
                return;
            sessions.TryRemove(sessionGuid, out var val);
        }

    }
}
