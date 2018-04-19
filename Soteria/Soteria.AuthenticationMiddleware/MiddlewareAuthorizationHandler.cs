using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    internal class MiddlewareAuthorizationHandler 
        : AttributeAuthorizationHandler<MiddlewareAuthorizationRequirment, SoteriaPermissionCheck>
    {
        IPermissionHandler _permissionHandler;
        public MiddlewareAuthorizationHandler(IPermissionHandler handler) 
            : base()
        {
            _permissionHandler = handler;
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

        private async Task<bool> AuthorizeAsync(ClaimsPrincipal user, List<string> permissions)
        {
            var identity = user.Identities.
                SingleOrDefault(t => t.AuthenticationType == AuthManager.MiddleWareInstanceName || t.AuthenticationType == $"{AuthManager.MiddleWareInstanceName}-jwt");
            if (identity == null || !identity.IsAuthenticated)
                return false;
            var permissionManager = new PermissionManager(_permissionHandler);
            var userPermissions = await Task.Run(() => { return permissionManager.GetPermission(identity.Name); });
            return userPermissions.Intersect(permissions).Count() > 0;
        }
        public override Task HandleAsync(AuthorizationHandlerContext context)
        {

            return base.HandleAsync(context);
        }
    }
}
