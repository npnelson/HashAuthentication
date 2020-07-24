using System;

namespace NetToolBox.HashAuthentication.Abstractions
{
    public interface IHashCalculator
    {
        Uri CalculateUriWithHash(Uri uri, TimeSpan expiration);
        bool IsValidUri(Uri uri);
    }
}
