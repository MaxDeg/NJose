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
using NJose.JsonSerialization;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NJose
{
    [JsonObject(MemberSerialization.OptIn)]
    public sealed class JsonWebToken
    {
        private static string[] reservedClaimNames = new[] { "iss", "sub", "aud", "exp", "nbf", "iat", "jti" };

        private readonly Dictionary<string, object> claims = new Dictionary<string, object>();

        [JsonProperty("aud")]
        [JsonConverter(typeof(CompactSingleItemCollectionConverter<string>))]
        private readonly ISet<string> audiences;

        public JsonWebToken()
        {
            this.audiences = new HashSet<string>();
            this.IssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this.Id = Guid.NewGuid().ToString();
        }

        [JsonProperty("iss")]
        public string Issuer { get; set; }

        [JsonProperty("sub")]
        public string Subject { get; set; }

        public ISet<string> Audience
        {
            get { return this.audiences; }
        }

        [JsonProperty("exp")]
        public long? ExpirationTime { get; set; }

        [JsonProperty("nbf")]
        public long? NotBefore { get; set; }

        [JsonProperty("iat")]
        public long IssuedAt { get; }

        [JsonProperty("jti")]
        public string Id { get; }

        public bool IsValid
        {
            get
            {
                var unixNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                return (!this.NotBefore.HasValue || this.NotBefore.Value < unixNow) &&
                    (!this.ExpirationTime.HasValue || this.ExpirationTime.Value > unixNow);
            }
        }

        public static JsonWebToken Parse(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var jwToken = JsonConvert.DeserializeObject<JsonWebToken>(token, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                ContractResolver = new IgnoreEmptyCollectionContractResolver()
            });

            return jwToken;
        }

        public void AddClaim(string key, object value)
        {
            if (reservedClaimNames.Contains(key))
                throw new ArgumentException("Cannot use reserved key with this method. User property instead", nameof(key));
            if (this.claims.ContainsKey(key))
                throw new ArgumentException("Claim with key " + key + " is already present in the JsonWebToken", nameof(key));

            this.claims[key] = value;
        }

        public void RemoveClaim(string key)
        {
            if (!this.claims.Remove(key))
                throw new KeyNotFoundException("Claim with key " + key + " not found in the JsonWebToken");
        }

        public TType FindClaim<TType>(string key)
        {
            object value;

            if (this.claims.TryGetValue(key, out value))
                return (TType)value;

            return default(TType);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                ContractResolver = new IgnoreEmptyCollectionContractResolver()
            });
        }
    }
}
