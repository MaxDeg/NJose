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
using System;
using System.Linq;

namespace NJose.JsonWebSignature
{
    public sealed class JWSJsonSerializer : IJsonWebSignatureSerializer
    {
        private readonly IDigitalSignatureAlgorithm[] algorithms;

        public JWSJsonSerializer(params IDigitalSignatureAlgorithm[] algorithms)
        {
            if (algorithms == null || algorithms.Length == 0)
                throw new ArgumentNullException(nameof(algorithms));

            this.algorithms = algorithms.ToArray();
        }

        public string Serialize(string token)
        {
            return this.Serialize(token, new JoseHeader());
        }

        public string Serialize(string token, JoseHeader header)
        {
            // sign token with all algorithm in the order
            throw new NotImplementedException();
        }

        public JsonWebToken Deserialize(string token)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            foreach (var alg in this.algorithms)
                alg.Dispose();
        }
    }
}
