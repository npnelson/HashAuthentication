using Microsoft.Extensions.Options;
using NetToolBox.DateTimeService;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace NetToolBox.HashAuthentication
{
    public sealed class HashCalculator
    {
        private readonly IDateTimeService _dateTimeService;
        private readonly IOptionsMonitor<List<HashKeyEntry>> _haskKeyOptionsMonitor;
        private RNGCryptoServiceProvider _rand = new RNGCryptoServiceProvider();

        public HashCalculator(IDateTimeService dateTimeService, IOptionsMonitor<List<HashKeyEntry>> haskKeyOptionsMonitor)
        {
            _dateTimeService = dateTimeService;
            _haskKeyOptionsMonitor = haskKeyOptionsMonitor;

        }

        public Uri CalculateUriWithHash(Uri uri, TimeSpan expiration)
        {
            return uri;
        }

        internal Uri CalculateUriToHash(Uri uri, TimeSpan expiration)
        {
            var activeItems = _haskKeyOptionsMonitor.CurrentValue.Where(x => x.IsActive).ToList();
            var randomIndex = RandomInteger(0, activeItems.Count - 1);
            var keyToUse = activeItems[randomIndex];

            var retval = new Uri(uri.ToString() + $"&expirationTime={_dateTimeService.CurrentDateTimeUTC.AddHours(5):yyyyMMddHHmmss}&hashKeyName={keyToUse.KeyName}");
            return retval;
        }
        //http://csharphelper.com/blog/2014/08/use-a-cryptographic-random-number-generator-in-c/
        // Return a random integer between a min and max value.
        private int RandomInteger(int min, int max)
        {
            uint scale = uint.MaxValue;
            while (scale == uint.MaxValue)
            {
                // Get four random bytes.
                byte[] four_bytes = new byte[4];
                _rand.GetBytes(four_bytes);

                // Convert that into an uint.
                scale = BitConverter.ToUInt32(four_bytes, 0);
            }

            // Add min to the scaled difference between max and min.
            return (int)(min + (max - min) *
                (scale / (double)uint.MaxValue));
        }
    }
}
