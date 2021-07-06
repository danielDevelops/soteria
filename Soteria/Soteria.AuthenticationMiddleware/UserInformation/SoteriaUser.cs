using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Reflection;
using System.Linq.Expressions;
using System.Collections;

namespace Soteria.AuthenticationMiddleware.UserInformation
{
    public enum AuthenticationMethod
    {
        NotSet,
        Windows,
        Forms
    }

    public class SoteriaUser<T> : ISoteriaUserValidation, ISoteriaUser<T> where T : class, new()
    {
        public T UserProperties { get; private set; }
        HttpContext context;
        private readonly ISessionHandler sessionHandler;

        public string GenericTypeName { get; private set; }
        public string UserName { get; private set; }
        public Guid SessionGuid { get; private set; }
        public bool ValidClaimInformation { get; private set; }
        public ClaimsIdentity Identity { get; private set; }
        public AuthenticationMethod AuthenticatedBy { get; private set; }
        public string ClaimID { get; private set; }
        public bool IsCookiePersistant { get; private set; }
        public void ClearRolesForUser()
            => PermissionManager.ClearPermissions(this.UserName);

        public void ChangeFieldValue<TValue>(Expression<Func<T,TValue>> field, TValue value) 
        {
            if (object.Equals(field, null))
                throw new NullReferenceException("A field must be selected to select a field?  That makes sense right?");

            MemberExpression expr = null;

            if (field.Body is MemberExpression)
                expr = (MemberExpression)field.Body;
            else if (field.Body is UnaryExpression)
                expr = (MemberExpression)((UnaryExpression)field.Body).Operand;
            else
                throw new ArgumentException($"Expression {field} not supported.", "Field");
            var fieldName = expr.Member.Name;

            ClearRolesForUser();
            var claim = Identity.FindFirst(fieldName);
            if (claim != null)
                Identity.RemoveClaim(claim);
            var serialziedValue = Newtonsoft.Json.JsonConvert.SerializeObject(value);
            Identity.AddClaim(new Claim(fieldName, serialziedValue));
           

            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(context, Identity.AuthenticationType);
            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignInAsync(context, new ClaimsPrincipal(Identity));

        }

        public async Task<bool> IsInRoleAsync(string role)
        {
            if (Identity == null || !Identity.IsAuthenticated || string.IsNullOrWhiteSpace(role))
                return false;
            var permissionHandler = (IPermissionHandler)context.RequestServices.GetService(typeof(IPermissionHandler));
            var permissonManager = new PermissionManager(permissionHandler);
            var permissions = await permissonManager.GetPermissionAsync(UserName);
            return permissions.Count(t => t.ToLower() == role.ToLower()) > 0;

        }

        public async Task<List<string>> GetPermissions()
        {
            var permissionHandler = (IPermissionHandler)context.RequestServices.GetService(typeof(IPermissionHandler));
            var permissionManager = new PermissionManager(permissionHandler);
            return await permissionManager.GetPermissionAsync(UserName);
        }

        public async Task<bool> IsAuthenticatedAsync()
        {
            if (Identity is null || !ValidClaimInformation)
                return false;
            var isSessionActive = await sessionHandler.IsSessionActiveAsync(SessionGuid);
            return ValidClaimInformation
                ? Identity.IsAuthenticated && isSessionActive
                : false;
        }

        public SoteriaUser(ClaimsPrincipal user, HttpContext context, ISessionHandler sessionHandler)
        {
            this.context = context;
            this.sessionHandler = sessionHandler;
            var identity = user.Identities.SingleOrDefault(t => t.AuthenticationType == AuthManager.MiddleWareInstanceName || t.AuthenticationType == $"{AuthManager.MiddleWareInstanceName}-jwt");
            Identity = identity;
            Init();
        }

        public SoteriaUser(ClaimsIdentity identity, HttpContext context, ISessionHandler sessionHandler)
        {
            this.context = context;
            this.sessionHandler = sessionHandler;
            Identity = identity;
            Init();
        }

        private void Init()
        {
            if (Identity == null || Identity.FindFirst(nameof(AuthenticatedBy)) == null || Identity.FindFirst(nameof(GenericTypeName)) == null)
            {
                ValidClaimInformation = false;
                return;
            }
            GenericTypeName = Identity.FindFirst(nameof(GenericTypeName)).Value;
            if (typeof(T).Name != GenericTypeName)
                throw new FormatException("The underlying security ticket doesn't match the generic type passed in for this authentication ticket.");
            ClaimID = Identity.Name;
            UserName = Identity.FindFirst(ClaimTypes.Name) != null ? Identity.FindFirst(ClaimTypes.Name).Value : "";
            SessionGuid = Identity.FindFirst(nameof(SessionGuid)) != null ? new Guid(Identity.FindFirst(nameof(SessionGuid)).Value) : Guid.Empty;
            var props = new T();
            foreach (var item in (typeof(T)).GetProperties())
            {
                if (Identity.FindFirst(item.Name) != null)
                {
                    var obj = Newtonsoft.Json.JsonConvert.DeserializeObject(Identity.FindFirst(item.Name).Value, item.PropertyType);
                    item.SetValue(props, obj);
                }
            }
            this.UserProperties = props;
            ValidClaimInformation = !string.IsNullOrWhiteSpace(UserName);

            AuthenticatedBy = (AuthenticationMethod)Enum.Parse(typeof(AuthenticationMethod), Identity.FindFirst(nameof(AuthenticatedBy)).Value, true);
            ValidClaimInformation = !string.IsNullOrWhiteSpace(UserName);
        }
    }
}
