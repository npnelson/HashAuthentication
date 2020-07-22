using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using NetToolBox.DateTimeService.TestHelper;
using System;
using System.Collections.Generic;
using Xunit;

namespace NetToolBox.HashAuthentication.Tests
{
    public class HashCalculatorTests
    {


        [Theory]
        [InlineData("http://localhost/RetrieveBlob?containerName=testcontainer&path=testpath&expirationTime=20200722173059&hashKeyName=key1&hashCode=PNd18qkQSAmWp5ZVpAnH3tUxSZY=", true)]
        [InlineData("http://localhost/RetrieveBlob?containerName=testcontainer&path=testpath&expirationTime=20300722173059&hashKeyName=key1&hashCode=PNd18qkQSAmWp5ZVpAnH3tUxSZY=", false)] //changed uri
        [InlineData("http://localhost/RetrieveBlob?containerName=testcontainer&path=testpath&expirationTime=20300722173059&hashKeyName=key1", false)] //no hashCode, should just return false, not throw
        //TODO: add a case with a valid uri, but past expired time
        public void ValidateUriTest(string uriString, bool isValid)
        {
            var fixture = new HashCalculatorTestFixture();
            var currentDateTime = new DateTime(2020, 7, 22, 12, 30, 59, 5);
            fixture.TestDateTimeServiceProvider.SetCurrentDateTimeUTC(currentDateTime);
            var uriToValidate = new Uri(uriString);
            var valid = fixture.HashCalculator.IsValidUri(uriToValidate);
            valid.Should().Be(isValid);
        }
        [Fact]
        public void CalculateUriToHashTest()
        {
            var fixture = new HashCalculatorTestFixture();
            var uri = new Uri("http://localhost/RetrieveBlob?containerName=testcontainer&path=testpath");
            var currentDateTime = fixture.TestDateTimeServiceProvider.CurrentDateTimeUTC;

            var uriToHash = fixture.HashCalculator.CalculateUriToHash(uri, TimeSpan.FromHours(5));
            var expectedUri = new Uri(uri.ToString() + $"&expirationTime={currentDateTime.AddHours(5):yyyyMMddHHmmss}&hashKeyName=key1");
            uriToHash.Uri.Should().Be(expectedUri);

        }

        [Fact]
        public void CalculateHashedUriTest()
        {
            var fixture = new HashCalculatorTestFixture();
            var currentDateTime = new DateTime(2020, 7, 22, 12, 30, 59, 5);
            fixture.TestDateTimeServiceProvider.SetCurrentDateTimeUTC(currentDateTime);

            var uri = new Uri("http://localhost/RetrieveBlob?containerName=testcontainer&path=testpath");
            var uriWithHash = fixture.HashCalculator.CalculateUriWithHash(uri, TimeSpan.FromHours(5));
            var expectedUri = new Uri(uri.ToString() + "&expirationTime=20200722173059&hashKeyName=key1&hashCode=PNd18qkQSAmWp5ZVpAnH3tUxSZY=");
            uriWithHash.Should().Be(expectedUri);

        }
    }

    public class HashCalculatorTestFixture
    {
        public readonly HashCalculator HashCalculator;
        public readonly TestDateTimeServiceProvider TestDateTimeServiceProvider = new TestDateTimeServiceProvider();
        public readonly List<HashKeyEntry> TestHashKeyEntries = new List<HashKeyEntry> { new HashKeyEntry { IsActive = true, KeyName = "key1", KeyValue = "password1" }, new HashKeyEntry { IsActive = false, KeyName = "key2", KeyValue = "password2" } };
        private readonly Mock<IOptionsMonitor<List<HashKeyEntry>>> MockOptions = new Mock<IOptionsMonitor<List<HashKeyEntry>>>();
        public HashCalculatorTestFixture()
        {
            MockOptions.SetupGet(x => x.CurrentValue).Returns(TestHashKeyEntries);
            HashCalculator = new HashCalculator(TestDateTimeServiceProvider, MockOptions.Object);
        }
    }
}
