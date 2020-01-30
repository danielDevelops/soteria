using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{    

    internal class PermissionManager
    {
        static readonly ConcurrentDictionary<string, UserPermission> _userPermissions = new ConcurrentDictionary<string, UserPermission>();
        IPermissionHandler _handler;
        public PermissionManager(IPermissionHandler handler)
        {
            _handler = handler;
        }
        public async Task<List<string>> GetPermission(string user)
        {
            var userPermission = new UserPermission();
            if (!_userPermissions.TryGetValue(user, out userPermission))
            {
                var permissions = await _handler.GetPermission(user);
                return ReplacePermissions(user, permissions);
            }
            if(_handler.PermissionsTimeout != null && (DateTime.Now - userPermission.Validated) > _handler.PermissionsTimeout)
            {
                var permissions = await _handler.GetPermission(user);
                return ReplacePermissions(user, permissions);
            }
            return userPermission.GetPermissions();
        }

        public static List<string> AddPermission(string user, string permission)
        {
            var mySet = new List<string>();
            _userPermissions.AddOrUpdate(user, 
                new UserPermission(permission), 
                (k, v) => { mySet = v.AddPermission(permission); return v; });
            return mySet;
        }
        public static List<string> ReplacePermissions(string user, List<string> permissions)
        {
            var mySet = new List<string>();
            _userPermissions.AddOrUpdate(user,
                (t => { var permission = new UserPermission(permissions); mySet = permission.GetPermissions(); return permission; }),
                (k, v) => { mySet = v.ReplacePermissions(permissions); return v; });
            return mySet;
        }
        public static List<string> RemovePermission(string user, string permission)
        {
            var mySet = new List<string>();
            _userPermissions.AddOrUpdate(user,
                new UserPermission(),
                (k, v) => { mySet = v.RemovePermission(permission); return v; }
                );
            return mySet;
        }
        public static bool ClearPermissions(string user)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(user))
                    return false;
                var permission = new UserPermission();
                return _userPermissions.TryRemove(user, out permission);
            }
            catch
            {
                return false;
            }
        }
    }
}
