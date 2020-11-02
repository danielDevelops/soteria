using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    internal class MiddlewareAuthorizationHandler 
        : AttributeAuthorizationHandler<MiddlewareAuthorizationRequirment, SoteriaPermissionCheck>
    {
        private readonly IPermissionHandler permissionHandler;
        private readonly ISessionHandler sessionHandler;

        public MiddlewareAuthorizationHandler(IPermissionHandler permissionHandler, ISessionHandler sessionHandler) 
            : base()
        {
            this.permissionHandler = permissionHandler;
            this.sessionHandler = sessionHandler;
        }
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, MiddlewareAuthorizationRequirment requirement, IEnumerable<SoteriaPermissionCheck> attributes)
        {
            var middleWareAuth = context.User.Identities
                .SingleOrDefault(t => t.AuthenticationType == AuthManager.MiddleWareInstanceName || t.AuthenticationType == $"{AuthManager.MiddleWareInstanceName}-jwt");
            if (middleWareAuth == null)
            {
                return;
            }
            if (!middleWareAuth.IsAuthenticated)
            {
                return;
            }
            if (!await SessionIsActiveAsync(context.User))
            {
                return;
            }
            foreach (var permissionAttribute in attributes)
            {
                if (permissionAttribute.PermissionList.Count > 0 
                    && !await AuthorizeAsync(context.User, permissionAttribute.PermissionList))
                {
                    return;
                }
            }
            context.Succeed(requirement);
        }
        
        private async Task<bool> SessionIsActiveAsync(ClaimsPrincipal user)
        {
            if (!sessionHandler.EnableSessionValidation)
                return true;
            var sessionManager = new SessionManager(sessionHandler);
            var val = user.FindFirst("SessionGuid") != null ? new Guid(user.FindFirst("SessionGuid").Value) : Guid.Empty;
            return await sessionManager.IsSessionActiveAsync(val);
        }

        private async Task<bool> AuthorizeAsync(ClaimsPrincipal user, List<string> permissions)
        {
            var identity = user.Identities.
                SingleOrDefault(t => t.AuthenticationType == AuthManager.MiddleWareInstanceName || t.AuthenticationType == $"{AuthManager.MiddleWareInstanceName}-jwt");
            if (identity == null || !identity.IsAuthenticated)
                return false;
            var permissionManager = new PermissionManager(permissionHandler);
            var userPermissions = await permissionManager.GetPermissionAsync(identity.Name);
            return userPermissions.Intersect(permissions).Count() > 0;
        }
        public override Task HandleAsync(AuthorizationHandlerContext context)
        {
            return base.HandleAsync(context);
        }
    }
}
