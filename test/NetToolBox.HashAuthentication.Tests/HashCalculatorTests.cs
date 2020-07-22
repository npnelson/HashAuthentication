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
        [Fact]
        public void CalculateUriToHashTest()
        {
            var fixture = new HashCalculatorTestFixture();
            var uri = new Uri("http://localhost/RetrieveBlob?containerName=testcontainer&path=testpath");
            var currentDateTime = fixture.TestDateTimeServiceProvider.CurrentDateTimeUTC;

            var uriToHash = fixture.HashCalculator.CalculateUriToHash(uri, TimeSpan.FromHours(5));
            var expectedUri = new Uri(uri.ToString() + $"&expirationTime={currentDateTime.AddHours(5):yyyyMMddHHmmss}&hashKeyName=key1");
            uriToHash.Should().Be(expectedUri);

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
