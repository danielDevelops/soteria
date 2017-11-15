using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Security.Principal;
using Soteria.AuthenticationMiddleware.UserInformation;
using Microsoft.AspNetCore.Http.Authentication;
using System.Reflection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace Soteria.AuthenticationMiddleware
{
    public static class AuthManager
    {
        public static readonly string MiddleWareInstanceName = "Soteria";
        public static void InitializeAuthenticationService<TPermissionHandler, GenericUser>(this IServiceCollection serviceCollection, 
            string loginPath, 
            string windowsLoginPath, 
            string accessDeniedPath, 
            string logoutPath, 
            bool forceSecureCookie,
            int defaultExpireMinutes,
            SymmetricSecurityKey key
            ) 
            where GenericUser: class, new()
            where TPermissionHandler : class, IPermissionHandler
        {
            serviceCollection.AddScoped<UserService<GenericUser>>();
            serviceCollection.AddTransient<IPermissionHandler, TPermissionHandler>();
            serviceCollection.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            serviceCollection.AddSingleton<IAuthorizationHandler, MiddlewareAuthorizationHandler>();
            serviceCollection.AddAuthorization(options =>
            {
                options.AddPolicy(MiddleWareInstanceName, policyBuilder =>
                {
                    policyBuilder.Requirements.Add(new MiddlewareAuthorizationRequirment());
                });
            });

            serviceCollection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = MiddleWareInstanceName;
                options.DefaultChallengeScheme = MiddleWareInstanceName;
                options.DefaultScheme = MiddleWareInstanceName;
            })
            .AddCookie(MiddleWareInstanceName, cookie =>
            {
                SetCookieAuthenticationOptions(cookie, loginPath, windowsLoginPath, accessDeniedPath, logoutPath, forceSecureCookie, defaultExpireMinutes);
            })
            .AddJwtBearer(MiddleWareInstanceName, jwt =>
            {
                jwt.TokenValidationParameters = CreateTokenParameters(key, "Soteria", "Soteria");
            });
            
                
        }
        public static void InitiializeAuthenticationApp(this IApplicationBuilder app)
        {
            app.UseAuthentication();
          
        }
        private static void SetCookieAuthenticationOptions(CookieAuthenticationOptions cookie, string loginPath, string windowsLoginPath, string accessDeniedPath, string logoutPath, bool forceSecureCookie, int defaultExpireMinutes)
        {
            cookie.LoginPath = new PathString(loginPath);
            cookie.LogoutPath = new PathString(logoutPath);
            cookie.AccessDeniedPath = accessDeniedPath;
            cookie.Cookie.Name = MiddleWareInstanceName;
            cookie.Cookie.SecurePolicy = forceSecureCookie ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            cookie.SlidingExpiration = true;
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(defaultExpireMinutes);
            cookie.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = ctx =>
                {
                    return Task.CompletedTask;
                },
                OnSigningIn = ctx =>
                {
                    var expireTime = (ctx.CookieOptions.Expires ?? DateTime.Now.AddMinutes(defaultExpireMinutes)) - DateTime.Now;
                    ctx.Options.ExpireTimeSpan = expireTime;
                    return Task.FromResult(0);
                },
                OnRedirectToLogin = async ctx =>
                {
                    if (ctx.Request.IsAjaxRequest())
                    {
                        ctx.HttpContext.Response.StatusCode = 401;
                        await ctx.Response.WriteAsync("Unauthenticated");
                        return;
                    }
                    var requestBase = GetRequestBasePath(ctx);
                    var queryString = "";
                    if (ctx.Request.Query.Count > 0)
                        queryString = "?" + string.Join("&", ctx.Request.Query.Select(t => $"{t.Key}={t.Value}"));
                    var redirectTo = System.Net.WebUtility.UrlEncode($"{requestBase}{ctx.Request.Path}{queryString}");
                    if (ctx.Request.Path == new PathString(windowsLoginPath))
                        return;
                    ctx.Response.Redirect($"{requestBase}{ctx.Options.LoginPath}?ReturnUrl={redirectTo}");
                    return;
                },
                OnRedirectToAccessDenied = async ctx =>
                {
                    if (ctx.Request.IsAjaxRequest())
                    {
                        ctx.HttpContext.Response.StatusCode = 403;
                        await ctx.Response.WriteAsync("Unauthorized");
                        return;
                    }
                    var requestBase = GetRequestBasePath(ctx);
                    ctx.Response.Redirect($"{requestBase}{ctx.Options.AccessDeniedPath}");
                    return;
                }
            };
        }

        private static TokenValidationParameters CreateTokenParameters(SymmetricSecurityKey key, string issuer, string audience)
        {
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(3)

            };
        }
        private static string GetRequestBasePath(RedirectContext<CookieAuthenticationOptions> ctx)
        {
            var requestBase = "";
            if (!ctx.Request.Host.Value.EndsWith("/"))
                requestBase = "/";
            if (ctx.Request.PathBase.ToString().Trim() != "/")
                requestBase = ctx.Request.PathBase;
            if (!requestBase.StartsWith("/") && requestBase != "/")
                requestBase = $"/{requestBase}";
            
            var path = $"{ctx.Request.Scheme}://{ctx.Request.Host}{requestBase}";
            return path.TrimEnd('/');
        }

        public static async Task<ClaimsIdentity> UserSignOn<T>(this HttpContext context, 
            string userName, 
            SoteriaUser<T>.AuthenticationMethod authenticateddBy, 
            string currentOperatingClient, 
            T genericUser,
            bool isPersistant) where T : class, new()
        {

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.NameIdentifier, userName.EnsureNullIsEmpty()),
                new Claim(nameof(SoteriaUser<T>.UserName), userName.EnsureNullIsEmpty()),
                new Claim(nameof(SoteriaUser<T>.AuthenticatedBy), authenticateddBy.ToString()),
                new Claim(nameof(SoteriaUser<T>.IsCookiePersistant), isPersistant.ToString()),
                new Claim(nameof(SoteriaUser<T>.GenericTypeName), typeof(T).Name)
            };
            foreach (var item in typeof(T).GetProperties())
            {
                var val = item.GetValue(genericUser);
                claims.Add(new Claim(item.Name, Newtonsoft.Json.JsonConvert.SerializeObject(val)));
            }

            var claim = new ClaimsIdentity(claims, MiddleWareInstanceName);

            var expireIn = TimeSpan.FromHours(8);
            if (isPersistant)
                expireIn = TimeSpan.FromDays(30);
            await AuthenticationHttpContextExtensions.SignInAsync(context,MiddleWareInstanceName,
                new ClaimsPrincipal(claim),
                new Microsoft.AspNetCore.Authentication.AuthenticationProperties { IsPersistent = isPersistant, ExpiresUtc = DateTime.UtcNow.Add(expireIn), AllowRefresh = true });
            return claim;
            
        }
        public static async Task UserSignOut(this HttpContext context)
        {
            var customUser = context.User.Identities.SingleOrDefault(t => t.Name == MiddleWareInstanceName);
            if (customUser?.Name != null)
                PermissionManager.ClearPermissions(customUser.Name);
            await AuthenticationHttpContextExtensions.SignOutAsync(context, MiddleWareInstanceName);
            
        }

        public static List<string> GetAllAssignedPermissions(Assembly assembly)
        {
            var permissions = new HashSet<string>();
            var attributeClassUsage = from type in assembly.GetTypes()
                                      where Attribute.IsDefined(type, typeof(SoteriaPermissionCheck))
                                      select type;
            foreach (var cls in attributeClassUsage)
            {
                var authorization = cls.GetCustomAttributes(typeof(SoteriaPermissionCheck));
                foreach (var item in authorization.SelectMany(t => ((SoteriaPermissionCheck)t).PermissionList))
                {
                    permissions.Add(item.Trim());
                }
            }
            var methodUsage = (from type in assembly.GetTypes()
                               from method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
                               where Attribute.IsDefined(method, typeof(SoteriaPermissionCheck))
                               select method);
            foreach (var method in methodUsage)
            {
                var authorization = method.GetCustomAttributes(typeof(SoteriaPermissionCheck));
                foreach (var item in authorization.SelectMany(t => ((SoteriaPermissionCheck)t).PermissionList))
                {
                    permissions.Add(item.Trim());
                }
            }

            return permissions.Where(t => !string.IsNullOrWhiteSpace(t)).ToList();
        }

    }
}
