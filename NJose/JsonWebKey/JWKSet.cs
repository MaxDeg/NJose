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
using System.Net.Http;
using System.Threading.Tasks;

namespace NJose.JsonWebKey
{
    // Could be encrypted in a JWE
    public sealed class JWKSet
    {
        [JsonProperty("keys")]
        private IEnumerable<CryptographicKey> set = null;

        private JWKSet() { }

        public CryptographicKey this[string keyId]
        {
            get { return this.set.FirstOrDefault(k => k.Id == keyId); }
        }

        public static async Task<JWKSet> GetAsync(Uri keySetUrl)
        {
            using (var client = new HttpClient())
            using (var response = await client.GetAsync(keySetUrl))
            {
                response.EnsureSuccessStatusCode();
                var keySet = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<JWKSet>(keySet);
            }
        }
    }
}
