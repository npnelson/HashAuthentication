using Microsoft.Extensions.Configuration;
using NetToolBox.HashAuthentication;
using NetToolBox.HashAuthentication.Abstractions;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("NetToolBox.HashAuthentication.Tests")]

namespace Microsoft.Extensions.DependencyInjection
{
    public static class HashAuthenticationServiceCollectionExtensions
    {
        public static IServiceCollection AddHashCode(this IServiceCollection services, IConfigurationSection configurationSection)
        {
            services.Configure<List<HashKeyEntry>>(configurationSection);
            services.AddDateTimeService();
            services.AddSingleton<IHashCalculator, HashCalculator>();
            return services;
        }
    }
}