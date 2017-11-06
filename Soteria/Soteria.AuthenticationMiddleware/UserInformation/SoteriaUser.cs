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
    public class SoteriaUser<T> : ISoteriaUserValidation, ISoteriaUser<T> where T : class, new()
    {
        public T UserProperties { get; private set; }
        public enum AuthenticationMethod
        {
            NotSet,
            Windows,
            Forms
        }
        HttpContext _context;
        public string GenericTypeName { get; private set; }
        public string UserName { get; private set; }
        public bool ValidClaimInformation { get; private set; }
        public ClaimsIdentity Identity { get; private set; }
        public bool IsAuthenticated { get; private set; }
        public AuthenticationMethod AuthenticatedBy { get; private set; }
        public string ClaimID { get; private set; }
        public bool IsCookiePersistant { get; private set; }
        public void ClearRolesForUser()
        {
            PermissionManager.ClearPermissions(this.UserName);
        }
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
           

            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(_context, Identity.AuthenticationType);
            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignInAsync(_context, new ClaimsPrincipal(Identity));

        }

        public bool IsInRole(string role)
        {
            if (Identity == null || !Identity.IsAuthenticated || string.IsNullOrWhiteSpace(role))
                return false;
            var permissionHandler = (IPermissionHandler)_context.RequestServices.GetService(typeof(IPermissionHandler));
            var permissonManager = new PermissionManager(permissionHandler);
            var permissions = permissonManager.GetPermission(UserName);
            return permissions.Count(t => t.ToLower() == role.ToLower()) > 0;

        }
        public List<string> GetPermissions()
        {
            var permissionHandler = (IPermissionHandler)_context.RequestServices.GetService(typeof(IPermissionHandler));
            var permissionManager = new PermissionManager(permissionHandler);
            return permissionManager.GetPermission(UserName);
        }
        public SoteriaUser(ClaimsPrincipal user, HttpContext context)
        {
            _context = context;
            var identity = user.Identities.SingleOrDefault(t => t.AuthenticationType == AuthManager.MiddleWareInstanceName);
            Init(identity);
        }
        public SoteriaUser(ClaimsIdentity identity, HttpContext context)
        {
            _context = context;
            Init(identity);
        }
        private void Init(ClaimsIdentity identity)
        {
            Identity = identity;
            if (identity == null || identity.FindFirst(nameof(AuthenticatedBy)) == null || identity.FindFirst(nameof(GenericTypeName)) == null)
            {
                IsAuthenticated = false;
                ValidClaimInformation = false;
                return;
            }
            GenericTypeName = identity.FindFirst(nameof(GenericTypeName)).Value;
            if (typeof(T).Name != GenericTypeName)
                throw new FormatException("The underlying security ticket doesn't match the generic type passed in for this authentication ticket.");
            ClaimID = identity.Name;
            UserName = identity.FindFirst(ClaimTypes.Name) != null ? identity.FindFirst(ClaimTypes.Name).Value : "";

            var props = new T();
            foreach (var item in (typeof(T)).GetProperties())
            {
                if (identity.FindFirst(item.Name) != null)
                {
                    var obj = Newtonsoft.Json.JsonConvert.DeserializeObject(identity.FindFirst(item.Name).Value, item.PropertyType);
                    item.SetValue(props, obj);
                }
            }
            this.UserProperties = props;
            ValidClaimInformation = !string.IsNullOrWhiteSpace(UserName);

            AuthenticatedBy = (AuthenticationMethod)Enum.Parse(typeof(AuthenticationMethod), identity.FindFirst(nameof(AuthenticatedBy)).Value, true);
            ValidClaimInformation = !string.IsNullOrWhiteSpace(UserName);
            IsAuthenticated = ValidClaimInformation ? identity.IsAuthenticated : false;
        }
    }
}
