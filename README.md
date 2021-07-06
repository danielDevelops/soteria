# soteria
### Authentication Middleware for .Net Core
This library is used for maintaining state of permissions on the server and claims data between the client and server.  This library uses cookie middleware manage this connection and perform login operations.

# Features
* Allows for proper 401 / 403 responses with ajax requests
* Performs redirection if not ajax request
* Prevents redirection if being used with Windows Auth on path
* Uses custom Authorizaiton attribute 
* Stores permissions on server 
  * Has user permission timeout / reload option
  * Uses DI to load permissions when not in memory
* Uses claims for user data
  * Claims properties are set using generic object
  * Claims are converted to / from object dynamically
  * Function to update claim using lambda expression

# Usage
* The InitializeAuthenticationService method must be called in Startup.cs file in the ConfigureServices method 
  ``` csharp 
  var hostUrl = "https://hostingUrl.com";
  var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("YoINeedAKey"));
  services.InitializeAuthenticationService<Security.PermissionHandler,Security.CustomUser>("/Auth/BeginAuth", "/Auth/WindowsAuth", "/Auth/NoAccess", "/Auth/Logout", false, 240, key, hostUrl, false);
  ```
* Additionally two lines must be added to the Configure method within Startup.cs file.
  * `app.InitializeAppAuthentication();` must be added to the beginning of the Configure method
  * `app.InitializeAppAuthorization();` must be added between the lines `app.UseRouting();` and `app.UseEndpoints();`
* Three classes must be created to be used with this library
  1. A library that implements IPermissionHandler from the library
      * this library is used for setting the timeout of the permissions for a user and to tell the library how to get the permissions for users.
        ``` csharp
        public class PermissionHandler : IPermissionHandler
        {   
            private readonly IHttpContextAccessor _context;

            public TimeSpan PermissionsTimeout { get { return new TimeSpan(0, 5, 0); } }

            public PermissionHandler(IHttpContextAccessor context)
            {
                _context = context;
            }
            public List<string> GetPermission(string username)
            {
                // If additional attributes are requried for your user you can get them here.
                var user = new Soteria.AuthenticationMiddleware.UserInformation.UserService<CustomUser>(_context);       
                /*
                    Write your custom code here to get permissions for your user.  
                    This could be used with Active Directory to make a call to get groups based on the user or could be used to make a database call.
                */
            }
        }
        ```
  2. A class must be created to store the data needed in the claims such as FullName or Email address
      * The only requirment for this class is that it implements an empty constructor 
  3. A class must be created that implements `ISessionHandler`.  If you do not wish to use the Session validation, you can set property on the class `public bool EnableSessionValidation => false;`

* One of the primary design considerations for this library is that each function of the application such as read, update, create, or delete is assigned an individual permission.  To that end, permissions is the primary method in which the solution was designed.  
  * To use the library for authorization and to get the data from the claims, the attribute [SoteriaPermissionCheck] should be added.  
  * To verify permissions on a controller add roles to the attribute [SoteriaPermissionCheck (Roles = "Some Role")]
* This library includes a UserService that will assist with getting the logged in user claim information
    ``` csharp
        [SoteriaPermissionCheck]
        public class HomeController : Controller
        {
            public HomeController(IHttpContextAccessor context)
            {
                var userService = new Soteria.AuthenticationMiddleware.UserInformation.UserService<Security.CustomUser>(context);
            }
        }
    ```

## Windows Authentication
* To use Windows authentication with this library with forms authentication you must use IIS
* Adding this to the web.config will force setting the User.Identity property on the controller for the path(s) specified
    ``` xml
    <location path="Auth/WindowsAuth">
    <system.webServer>
      <security>
        <authentication>
          <windowsAuthentication enabled="true" />
          <anonymousAuthentication enabled="false" />
        </authentication>
      </security>
    </system.webServer>
  </location>
    ```
* *Note be sure to set both Anonymous and Windows authentication to active in Visual studio to get the credentials passed through from IIS
* In the path that is set in the Startup.cs and set in the web.config you can use User.Identity.Name to get the logged in user name
    ``` csharp
    var winUserName = User.Identity.Name;
    ```
