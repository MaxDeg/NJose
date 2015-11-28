using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.Algorithms;
using NJose.Extensions;
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
