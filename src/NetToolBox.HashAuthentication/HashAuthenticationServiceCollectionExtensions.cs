using Microsoft.Extensions.Configuration;
using NetToolBox.HashAuthentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("NetToolBox.HashAuthentication.Tests")]

namespace Microsoft.Extensions.DependencyInjection
{
    public static class HashAuthenticationServiceCollectionExtensions
    {
        /// <summary>
        /// This overload will be deprecated as soon as Azure Functions supports ASPNet core style configuration
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        public static IServiceCollection AddHashKeyAuthentication(this IServiceCollection services)
        {
            var optionsRegistered = services.Any(x => x.ServiceType.GenericTypeArguments.Any(x => x == typeof(List<HashKeyEntry>)));
            if (!optionsRegistered) throw new InvalidOperationException("You must register options for of type List<HashKeyEntry for hashkeyauthentication");
            services.AddDateTimeService();
            services.AddSingleton<HashCalculator>();
            return services;
        }

        public static IServiceCollection AddHashKeyAuthentication(this IServiceCollection services, IConfigurationSection configurationSection)
        {
            services.Configure<List<HashKeyEntry>>(configurationSection);
            services.AddHashKeyAuthentication();
            return services;
        }
    }
}
