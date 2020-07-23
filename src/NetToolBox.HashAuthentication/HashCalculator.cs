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
            var randomIndex = RandomNumberGenerator.GetInt32(activeItems.Count); //the upper bound is exclusive, so that's why we go with count instead of count -1
            var keyToUse = activeItems[randomIndex];
            var uriString = uri.ToString();
            var retval = (new Uri(uriString + $"{(uriString.Contains('?') ? '&' : '?')}expirationTime={_dateTimeService.CurrentDateTimeUTC.Add(expiration):yyyyMMddHHmmss}&hashKeyName={keyToUse.KeyName}"), keyToUse);
            return retval;
        }

    }

}
