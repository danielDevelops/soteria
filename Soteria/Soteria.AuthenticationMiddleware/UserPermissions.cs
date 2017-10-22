using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    internal class UserPermission
    {
        public DateTime Validated { get; private set; }
        HashSet<string> _permissions;
        public UserPermission()
        {
            _permissions = new HashSet<string>();
            Validated = DateTime.Now;
        }
        public UserPermission(string permission) : this()
        {
            _permissions.Add(permission);
        }
        public UserPermission(List<string> permissions) : this()
        {
            _permissions.UnionWith(permissions);
        }
        public List<string> AddPermission(string permission)
        {
            _permissions.Add(permission);
            return _permissions.ToList();
        }
        public List<string> GetPermissions()
        {
            return _permissions.ToList();
        }
        public List<string> ReplacePermissions(List<string> list)
        {
            Validated = DateTime.Now;
            _permissions = null;
            _permissions = new HashSet<string>();
            _permissions.UnionWith(list);
            return _permissions.ToList();
        }
        public List<string> RemovePermission(string permission)
        {
            _permissions.RemoveWhere(t => t.ToLower() == permission.ToLower());
            return _permissions.ToList();
        }
    }
}
