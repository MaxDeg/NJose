﻿/******************************************************************************
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
using NJose.JsonSerialization;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace NJose
{
    public sealed class JoseHeader
    {
        // Extension headers - must be defined in critical header
        [JsonExtensionData]
        private readonly Dictionary<string, object> headers = new Dictionary<string, object>();

        public JoseHeader()
        {
            this.X509CertificateChain = new HashSet<string>();
            this.Critical = new HashSet<string>();
        }

        [Obsolete]
        public JoseHeader(string token) { }

        [JsonProperty("alg")]
        public string Algorithm { get; internal set; }

        [JsonProperty("typ"), JsonConverter(typeof(JoseTypeHeaderConverter))]
        public string Type { get; set; }

        [JsonProperty("cty"), JsonConverter(typeof(JoseTypeHeaderConverter))]
        public string ContentType { get; set; }

        [JsonProperty("jku")]
        public Uri JwkSetUrl { get; set; }

        [JsonProperty("jwk")]
        public string JsonWebKey { get; set; }

        [JsonProperty("kid")]
        public string KeyId { get; set; }

        [JsonProperty("x5u")]
        public Uri X509Url { get; set; }

        [JsonProperty("x5c")]
        public ISet<string> X509CertificateChain { get; private set; }
        
        [JsonProperty("x5t")]
        public string X509Thumbprint { get; set; }

        [JsonProperty("crit")]
        internal ISet<string> Critical { get; private set; }
        
        public object this[string key]
        {
            get { return this.headers[key]; }
            set { this.Add(key, value); }
        }

        public void Add(string key, object value)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (value == null) throw new ArgumentNullException(nameof(value));

            if (!this.Critical.Contains(key))
                this.Critical.Add(key);

            this.headers[key] = value;
        }

        public void Remove(string key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            this.Critical.Remove(key);
            this.headers.Remove(key);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                ContractResolver = new IgnoreEmptyCollectionContractResolver()
            });
        }

        public static JoseHeader Parse(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var joseHeader = JsonConvert.DeserializeObject<JoseHeader>(token, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                ContractResolver = new IgnoreEmptyCollectionContractResolver()
            });

            return joseHeader;
        }
        
        [OnDeserialized]
        private void OnDeserialized(StreamingContext context)
        {
            if (this.headers.Count != this.Critical.Count)
                throw new InvalidJoseHeaderException();

            foreach (var key in this.headers.Keys)
                if (!this.Critical.Contains(key))
                    throw new InvalidJoseHeaderException(key);
        }
    }
}
