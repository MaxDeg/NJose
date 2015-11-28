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

using NJose.Algorithms;
using NJose.Extensions;
using System;
using System.Linq;
using System.Text;

namespace NJose.Serialization
{
    public sealed class JWSCompactSerializer : IJsonWebSignatureSerializer
    {
        private readonly IJWADigitalSignature algorithm;

        public JWSCompactSerializer(IJWADigitalSignature algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            this.algorithm = algorithm;
        }

        public string Serialize(JsonWebToken token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var header = new JoseHeader { Algorithm = this.algorithm.Name };

            var toSign = string.Join(".", header.ToJson().ToBase64Url(), token.ToJson().ToBase64Url());
            var signature = algorithm.Sign(Encoding.ASCII.GetBytes(toSign)).ToBase64Url();

            if (signature == null)
                return toSign;
            else
                return string.Join(".", toSign, signature);
        }

        public JsonWebToken Deserialize(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var splittedToken = token.Split('.');

            // Minimal number of parts in a JWS compact token is 2 in case of "none" algorithm
            if (splittedToken.Length < 2)
                throw new InvalidJsonWebSignatureToken("invalid token format");

            var header = new JoseHeader(splittedToken[0]);

            // the algorithm must be the same to avoid vulnerabilities
            if (this.algorithm.Name != header.Algorithm)
                throw new InvalidJsonWebSignatureToken("Algorithms mismatch");

            var toSign = string.Join(".", splittedToken.Take(2));

            // if Algorithm is none signature is null
            if (!this.algorithm.Verify(Encoding.ASCII.GetBytes(toSign), splittedToken.Skip(2).SingleOrDefault().FromBase64Url()))
                throw new InvalidJsonWebSignatureToken("signatures mismatch");

            var jwt = new JsonWebToken(splittedToken[1]);

            return jwt.IsValid ? jwt : null;
        }

        public void Dispose()
        {
            this.algorithm?.Dispose();
        }
    }
}
