using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Soteria.AuthenticationMiddleware
{
    internal abstract class AttributeAuthorizationHandler<TRequirement, TAttribute> : AuthorizationHandler<TRequirement>
       where TRequirement : IAuthorizationRequirement
       where TAttribute : SoteriaPermissionCheck
    {
        public AttributeAuthorizationHandler() : base()
        {

        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement)
        {
            var attributes = new List<TAttribute>();

            var httpContext = context.Resource as HttpContext;
            var endpoint = httpContext.GetEndpoint();
           
            if (endpoint.Metadata.OfType<SoteriaPermissionCheck>().Any())
            {
                attributes.AddRange(endpoint.Metadata.OfType<TAttribute>());

                return HandleRequirementAsync(context, requirement, attributes);
            }

            var action = (context.Resource as AuthorizationFilterContext)?.ActionDescriptor as ControllerActionDescriptor;
            if (action != null)
            {
                attributes.AddRange(GetAttributes(action.ControllerTypeInfo.UnderlyingSystemType));
                attributes.AddRange(GetAttributes(action.MethodInfo));
            }
            return HandleRequirementAsync(context, requirement, attributes);
        }
        protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement, IEnumerable<TAttribute> attributes);

        private static IEnumerable<TAttribute> GetAttributes(MemberInfo memberInfo)
        {
            return memberInfo.GetCustomAttributes(typeof(TAttribute), false).Cast<TAttribute>();
        }
    }
}
