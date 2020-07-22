using Microsoft.Extensions.Options;
using NetToolBox.DateTimeService;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NetToolBox.HashAuthentication
{
    public sealed class HashCalculator
    {
        private readonly IDateTimeService _dateTimeService;
        private readonly IOptionsMonitor<List<HashKeyEntry>> _haskKeyOptionsMonitor;
        private readonly RNGCryptoServiceProvider _rand = new RNGCryptoServiceProvider();

        public HashCalculator(IDateTimeService dateTimeService, IOptionsMonitor<List<HashKeyEntry>> haskKeyOptionsMonitor)
        {
            _dateTimeService = dateTimeService;
            _haskKeyOptionsMonitor = haskKeyOptionsMonitor;

        }

        public bool IsValidUri(Uri uri)
        {
            //first strip the hashcode
            var uriString = uri.ToString();

            //find hashCode=
            var hashCodeIndex = uriString.IndexOf("hashCode=");
            if (hashCodeIndex <= 0) return false;
            var hashCodeSent = uriString.Substring(hashCodeIndex + 9);
            var uriWithoutHashCode = uriString.Substring(0, hashCodeIndex - 1);
            //find keyName=
            var keyNameIndex = uriString.IndexOf("hashKeyName=");
            if (keyNameIndex <= 0) return false;
            var keyName = uriWithoutHashCode.Substring(keyNameIndex + 12);
            var keyPassword = _haskKeyOptionsMonitor.CurrentValue.Single(x => x.KeyName == keyName).KeyValue;

            var hashCodeExpected = CalculateHashCodeForUri(new Uri(uriWithoutHashCode), keyPassword);

            var currentTime = _dateTimeService.CurrentDateTimeUTC;
            var expirationTimeIndex = uriWithoutHashCode.IndexOf("expirationTime");
            if (expirationTimeIndex <= 0) return false;
            var expirationTime = DateTime.ParseExact(uriWithoutHashCode.Substring(expirationTimeIndex + 15, 14), "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
            if (expirationTime < currentTime) return false;

            return hashCodeSent == hashCodeExpected;
        }



        public Uri CalculateUriWithHash(Uri uri, TimeSpan expiration)
        {
            var uriToHash = CalculateUriToHash(uri, expiration);
            var hashCode = CalculateHashCodeForUri(uriToHash.Uri, uriToHash.HashKeyEntry.KeyValue);
            var retval = new Uri(Uri.EscapeUriString($"{uriToHash.Uri}&hashCode={hashCode}"));
            return retval;
        }

        internal string CalculateHashCodeForUri(Uri uri, string hashPassword)
        {
            var sha1 = new HMACSHA1(Encoding.UTF8.GetBytes(hashPassword));
            var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(uri.ToString()));
            var encoded = Convert.ToBase64String(hash);
            return encoded;
        }
        internal (Uri Uri, HashKeyEntry HashKeyEntry) CalculateUriToHash(Uri uri, TimeSpan expiration)
        {
            var activeItems = _haskKeyOptionsMonitor.CurrentValue.Where(x => x.IsActive).ToList();
            var randomIndex = RandomInteger(0, activeItems.Count - 1);
            var keyToUse = activeItems[randomIndex];

            var retval = (new Uri(uri.ToString() + $"&expirationTime={_dateTimeService.CurrentDateTimeUTC.Add(expiration):yyyyMMddHHmmss}&hashKeyName={keyToUse.KeyName}"), keyToUse);
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
