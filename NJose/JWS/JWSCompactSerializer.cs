using NJose.JWA;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JWS
{
    public sealed class JWSCompactSerializer : IJsonWebSignatureSerializer
    {
        private readonly IJsonWebAlgorithm algorithm;

        public JWSCompactSerializer(IJsonWebAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public string Serialize(JsonWebToken token)
        {
            var header = new JoseHeader { Algorithm = this.algorithm.Name };

            var toSign = string.Join(".", header.ToJson().ToBase64Url(), token.ToJson().ToBase64Url());
            var signature = algorithm.Sign(Encoding.ASCII.GetBytes(toSign)).ToBase64Url();

            return string.Join(".", toSign, signature);
        }

        public JsonWebToken Deserialize(string token)
        {
            var splittedToken = token.Split('.');

            // Minimal number of parts in a JWS compact token is 2 in case of "none" algorithm
            if (splittedToken.Length < 2)
                throw new InvalidJsonWebSignatureToken("invalid token format");

            var header = new JoseHeader(splittedToken[0]);

            // the algorithm must be the same to avoid vulnerabilities
            if (this.algorithm.Name != header.Algorithm)
                throw new InvalidJsonWebSignatureToken("Algorithms mismatch");

            // special case for alg  == "none"
            // else
            if (splittedToken.Length != 3)
                throw new InvalidJsonWebSignatureToken("invalid token format");

            var toSign = string.Join(".", splittedToken.Take(2));
            var signature = algorithm.Sign(Encoding.ASCII.GetBytes(toSign)).ToBase64Url();

            if (splittedToken.Last() != signature)
                throw new InvalidJsonWebSignatureToken("signatures mismatch");

            var jwt = new JsonWebToken(splittedToken[1]);
                        
            return jwt.IsValid ? jwt : null;
        }
    }
}
