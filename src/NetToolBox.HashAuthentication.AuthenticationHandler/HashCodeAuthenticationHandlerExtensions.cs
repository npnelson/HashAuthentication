using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace NetToolBox.HashAuthentication.AuthenticationHandler
{
    public static class HashCodeAuthenticationHandlerExtensions
    {
        private const string DefaultHashCodeAuthenticationName = "HashCodeAuthentication";

        public static void AddHashCodeAuthentication(this IServiceCollection services, IConfigurationSection configurationSection)
        {
            services.AddHashCode(configurationSection);
            services.AddAuthentication(DefaultHashCodeAuthenticationName).AddScheme<AuthenticationSchemeOptions, HashCodeAuthenticationHandler>(DefaultHashCodeAuthenticationName, options => { });
        }
    }
}
