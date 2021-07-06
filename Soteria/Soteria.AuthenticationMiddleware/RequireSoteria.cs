using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Soteria.AuthenticationMiddleware;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Soteria.AuthenticationMiddleware
{
    [HtmlTargetElement(Attributes = "require-soteria")]
    public class RequireSoteria : TagHelper
    {
        public enum ProcessType
        {
            RequireAuthorization = 0,
            RequireNotAuthorized = 1,
            RequireNegativePermission = 2
        }
        public string Permission { get; set; } = "";
        public ProcessType Type { get; set; } = ProcessType.RequireAuthorization;
        private readonly UserInformation.ISoteriaUserValidation currentUserValidation;
        public RequireSoteria(UserInformation.ISoteriaUserValidation currentUserValidation)
        {
            this.currentUserValidation = currentUserValidation;
        }

        public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            if (Type == ProcessType.RequireNotAuthorized && await currentUserValidation.IsAuthenticatedAsync())
                output.SuppressOutput();
            if (Type == ProcessType.RequireAuthorization && !(await HasPermission(Permission.Trim())))
                output.SuppressOutput();
            if (Type == ProcessType.RequireNegativePermission && await HasPermission(Permission.Trim()))
                output.SuppressOutput();
        }
        private async Task<bool> HasPermission(string role)
        {
            if (!await currentUserValidation.IsAuthenticatedAsync())
                return false;
            if (string.IsNullOrWhiteSpace(role))
                return true;
            return await currentUserValidation.IsInRoleAsync(Permission);
        }
    }
}
