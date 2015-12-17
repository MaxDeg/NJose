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

using Microsoft.Owin.Hosting;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.JsonWebKey;
using NJose.JsonWebSignature;
using NJose.JsonWebSignature.Algorithms;
using Owin;
using System;
using System.IO;
using System.Threading.Tasks;

namespace NJose.Test
{
    [TestClass]
    public class JWSSerializationUnitTest
    {
        private Uri keySetUri = new Uri("http://localhost:3727");
        private IDisposable server;

        [TestInitialize]
        public void Initialize()
        {
            var content = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keyset.json"));

            this.server = WebApp.Start(this.keySetUri.ToString(), app => app.Run(c =>
            {
                c.Response.ContentType = "application/json";
                return c.Response.WriteAsync(content);
            }));
        }

        [TestCleanup]
        public void Cleanup()
        {
            this.server?.Dispose();
        }

        [TestMethod]
        public void Verify_None_Algorithm_Serialization()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer();
            var strToken = serializer.Serialize(token.ToJson());
            var deserializedToken = serializer.Deserialize(strToken);
            
            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void HS256_Algorithm_Key_Too_Short()
        {
            new JWSCompactSerializer(new HS256Algorithm("1To680X8yGFe8wEFu"));
        }

        [TestMethod]
        public async Task Verify_HS256_Algorithm_Serialization()
        {
            var keySet = await JWKSet.GetAsync(this.keySetUri);
            var key = keySet["hs-256"];

            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS256Algorithm(key));
            var strToken = serializer.Serialize(token.ToJson());
            var deserializedToken = serializer.Deserialize(strToken);

            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void HS384_Algorithm_Key_Too_Short()
        {
            new JWSCompactSerializer(new HS384Algorithm("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
        }

        [TestMethod]
        public async Task Verify_HS384_Algorithm_Serialization()
        {
            var keySet = await JWKSet.GetAsync(this.keySetUri);
            var key = keySet["hs-384"];

            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS384Algorithm(key));
            var strToken = serializer.Serialize(token.ToJson());
            var deserializedToken = serializer.Deserialize(strToken);

            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void HS512_Algorithm_Key_Too_Short()
        {
            new JWSCompactSerializer(new HS512Algorithm("1To680X8yGFe8wEFu5Ye8bW735CF9j6D1To680X8yGFe8wEFu5Ye8bW735CF9j6"));
        }

        [TestMethod]
        public async Task Verify_HS512_Algorithm_Serialization()
        {
            var keySet = await JWKSet.GetAsync(this.keySetUri);
            var key = keySet["hs-512"];

            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS512Algorithm(key));
            var strToken = serializer.Serialize(token.ToJson());
            var deserializedToken = serializer.Deserialize(strToken);

            Assert.AreEqual(token.ToJson(), deserializedToken.ToJson());
        }
    }
}
