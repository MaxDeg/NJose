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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.Algorithms;
using NJose.Serialization;
using System;

namespace NJose.Test
{
    [TestClass]
    public class JWSSerializationUnitTest
    {
        [TestMethod]
        public void Verify_None_Algorithm_Serialization()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new NoDigitalSignature());
            var strToken = serializer.Serialize(token);
            var deserializedToken = serializer.Deserialize(strToken);
            
            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void HS256_Algorithm_Key_Too_Short()
        {
            new JWSCompactSerializer(new HS256DigitalSignature("1To680X8yGFe8wEFu"));
        }

        [TestMethod]
        public void Verify_HS256_Algorithm_Serialization()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS256DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var strToken = serializer.Serialize(token);
            var deserializedToken = serializer.Deserialize(strToken);

            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void HS384_Algorithm_Key_Too_Short()
        {
            new JWSCompactSerializer(new HS384DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
        }

        [TestMethod]
        public void Verify_HS384_Algorithm_Serialization()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS384DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D1To680X8yGFe8wEF"));
            var strToken = serializer.Serialize(token);
            var deserializedToken = serializer.Deserialize(strToken);

            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void HS512_Algorithm_Key_Too_Short()
        {
            new JWSCompactSerializer(new HS512DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D1To680X8yGFe8wEFu5Ye8bW735CF9j6"));
        }

        [TestMethod]
        public void Verify_HS512_Algorithm_Serialization()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS512DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            var strToken = serializer.Serialize(token);
            var deserializedToken = serializer.Deserialize(strToken);

            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }
    }
}
