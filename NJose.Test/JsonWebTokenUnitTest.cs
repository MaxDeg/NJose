/******************************************************************************
    Copyright 2015 Maxime Degallaix

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
******************************************************************************/

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.JsonWebSignature;
using System.Threading;
using NJose.JsonWebSignature.Algorithms;

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

            var serializer = new JWSCompactSerializer(new HS256Algorithm("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var deserializedToken = serializer.Deserialize(serializer.Serialize(token.ToJson()));

            Assert.IsFalse(deserializedToken.IsValid);
        }

        [TestMethod]
        public void Should_Token_Not_Yet_Valid()
        {
            var token = new JsonWebToken { Issuer = "joe", NotBefore = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() };
            token.AddClaim("http://example.com/is_root", true);

            Assert.IsFalse(token.IsValid);

            var serializer = new JWSCompactSerializer(new HS256Algorithm("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var deserializedToken = serializer.Deserialize(serializer.Serialize(token.ToJson()));

            Assert.IsFalse(deserializedToken.IsValid);
        }

        [TestMethod]
        public void Should_Token_Future_Valid()
        {
            var token = new JsonWebToken { Issuer = "joe", NotBefore = DateTimeOffset.UtcNow.AddMilliseconds(500).ToUnixTimeSeconds() };
            token.AddClaim("http://example.com/is_root", true);

            Assert.IsFalse(token.IsValid);

            var serializer = new JWSCompactSerializer(new HS256Algorithm("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var deserializedToken = serializer.Deserialize(serializer.Serialize(token.ToJson()));

            Assert.IsFalse(deserializedToken.IsValid);

            Thread.Sleep(1500);
            Assert.IsTrue(deserializedToken.IsValid);
        }
    }
}
