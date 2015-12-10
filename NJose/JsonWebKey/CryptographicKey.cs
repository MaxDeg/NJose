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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JsonWebKey
{
    [JsonObject(MemberSerialization.OptIn)]
    public class CryptographicKey
    {
        internal CryptographicKey() { }

        internal CryptographicKey(Uri x509Url, ISet<string> x509Chain, string x509Thumbprint)
        {
            this.X509Url = x509Url;
            this.X509CertificateChain = x509Chain;
            this.X509Thumbprint = x509Thumbprint;
        }

        [JsonProperty("kid")]
        public string Id { get; private set; }

        [JsonProperty("kty")]
        public string Type { get; private set; }
        
        // Use and Operations
        // The "use" and "key_ops" JWK members SHOULD NOT be used together;
        // however, if both are used, the information they convey MUST be
        // consistent.
        [JsonProperty("use")]
        public string Use { get; private set; }

        [JsonProperty("key_ops")]
        public IEnumerable<string> Operations { get; private set; }

        [JsonProperty("alg")]
        public string Algorithm { get; private set; }
        
        [JsonProperty("x5u")]
        public Uri X509Url { get; set; }

        [JsonProperty("x5c")]
        public ISet<string> X509CertificateChain { get; private set; }

        [JsonProperty("x5t")]
        public string X509Thumbprint { get; set; }
    }
}
