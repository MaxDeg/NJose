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

using NJose.JsonWebSignature.Algorithms;
using NJose.Extensions;
using System;
using System.Linq;

using static System.Text.Encoding;

namespace NJose.JsonWebSignature
{
    public sealed class JWSCompactSerializer : IJsonWebSignatureSerializer
    {
        private readonly IDigitalSignatureAlgorithm algorithm;
        
        public JWSCompactSerializer()
        {
            this.algorithm = new NoAlgorithm();
        }

        public JWSCompactSerializer(IDigitalSignatureAlgorithm algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            this.algorithm = algorithm;
        }

        public string Serialize(string payload)
        {
            return this.Serialize(payload, new JoseHeader());
        }

        public string Serialize(string payload, JoseHeader header)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            header.Algorithm = this.algorithm.Name;
            
            var signature = algorithm.Sign(header, payload).ToBase64Url(); 

            return string.Join(".", header.ToJson().ToBase64Url(), payload.ToBase64Url(), signature);
        }

        public JsonWebToken Deserialize(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var splittedToken = token.Split('.');

            // JWS compact token has always 3 parts
            if (splittedToken.Length != 3)
                throw new InvalidJsonWebSignatureToken("invalid token format");

            var header = JoseHeader.Parse(UTF8.GetString(splittedToken[0].FromBase64Url()));

            // the algorithm must be the same to avoid vulnerabilities
            if (this.algorithm.Name != header.Algorithm)
                throw new InvalidJsonWebSignatureToken("Algorithms mismatch");

            var payload = UTF8.GetString(splittedToken[1].FromBase64Url());
            var signature = splittedToken.Skip(2).Single().FromBase64Url();

            if (!this.algorithm.Verify(header, payload, signature))
                throw new InvalidJsonWebSignatureToken("signatures mismatch");

            return new JsonWebToken(payload);
        }

        public void Dispose()
        {
            this.algorithm?.Dispose();
        }
    }
}
