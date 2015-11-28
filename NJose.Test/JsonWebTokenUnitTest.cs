using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.Serialization;
using NJose.Algorithms;
using System.Threading;

namespace NJose.Test
{
    [TestClass]
    public class JsonWebTokenUnitTest
    {
        [TestMethod]
        public void Should_Token_Expired()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds() };
            token.AddClaim("http://example.com/is_root", true);

            Assert.IsFalse(token.IsValid);

            var serializer = new JWSCompactSerializer(new HS256DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var deserializedToken = serializer.Deserialize(serializer.Serialize(token));

            Assert.IsFalse(deserializedToken.IsValid);
        }

        [TestMethod]
        public void Should_Token_Not_Yet_Valid()
        {
            var token = new JsonWebToken { Issuer = "joe", NotBefore = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
            token.AddClaim("http://example.com/is_root", true);

            Assert.IsFalse(token.IsValid);

            var serializer = new JWSCompactSerializer(new HS256DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var deserializedToken = serializer.Deserialize(serializer.Serialize(token));

            Assert.IsFalse(deserializedToken.IsValid);
        }

        [TestMethod]
        public void Should_Token_Future_Valid()
        {
            var token = new JsonWebToken { Issuer = "joe", NotBefore = DateTimeOffset.UtcNow.AddMilliseconds(500).ToUnixTimeSeconds() };
            token.AddClaim("http://example.com/is_root", true);

            Assert.IsFalse(token.IsValid);

            var serializer = new JWSCompactSerializer(new HS256DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var deserializedToken = serializer.Deserialize(serializer.Serialize(token));

            Assert.IsFalse(deserializedToken.IsValid);

            Thread.Sleep(1500);
            Assert.IsTrue(deserializedToken.IsValid);
        }
    }
}
