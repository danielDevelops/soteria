using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class SoteriaPermissionCheck : Attribute, IAuthorizeData
    {
        internal List<string> PermissionList { get; private set; }
        public string Policy { get { return AuthManager.MiddleWareInstanceName; } set => throw new NotImplementedException($"You cannot set the policy for the {nameof(SoteriaPermissionCheck)} Attribute!!!"); }

        public string Roles
        {
            get
            {
                return null;
            }
            set
            {
                SetupPermissionList(value);
            }
        }


        public string AuthenticationSchemes { get { return AuthManager.MiddleWareInstanceName; } set => throw new NotImplementedException($"You cannot set the active authentication schemes for the {nameof(SoteriaPermissionCheck)} Attribute!!!"); }

        public SoteriaPermissionCheck() 
        {
            PermissionList = new List<string>();
        }
        public SoteriaPermissionCheck(string permissions) : this()
        {
            SetupPermissionList(permissions);
        }

        private void SetupPermissionList(string permissions)
        {
            if (!string.IsNullOrWhiteSpace(permissions) && permissions.Contains(","))
                PermissionList = permissions.Split(',').ToList();
            else if (!string.IsNullOrWhiteSpace(permissions))
                PermissionList.Add(permissions);
        }
    }
}
