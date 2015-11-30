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

namespace NJose
{
    public sealed class JsonWebToken
    {
        private readonly Dictionary<string, object> claims = new Dictionary<string, object>();

        public JsonWebToken()
        {
            this.InitStandardClaims();
            this.claims["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this.claims["jti"] = Guid.NewGuid().ToString();
        }

        public JsonWebToken(string token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            this.InitStandardClaims();

            foreach (var pair in JsonConvert.DeserializeObject<Dictionary<string, object>>(token))
                this.claims[pair.Key] = pair.Value;
        }

        public string Issuer
        {
            get { return (string)this.claims["iss"]; }
            set { this.claims["iss"] = value; }
        }

        public string Subject
        {
            get { return (string)this.claims["sub"]; }
            set { this.claims["sub"] = value; }
        }

        // Aray or single value ... need converter
        public IList<string> Audience
        {
            get { return (IList<string>)this.claims["aud"]; }
        }

        public long? ExpirationTime
        {
            get { return (long?)this.claims["exp"]; }
            set { this.claims["exp"] = value; }
        }

        public long? NotBefore
        {
            get { return (long?)this.claims["nbf"]; }
            set { this.claims["nbf"] = value; }
        }

        public long IssuedAt
        {
            get { return (long)this.claims["iat"]; }
        }

        public string Id
        {
            get { return (string)this.claims["jti"]; }
        }

        public bool IsValid
        {
            get
            {
                var unixNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                return (!this.NotBefore.HasValue || this.NotBefore.Value < unixNow) &&
                    (!this.ExpirationTime.HasValue || this.ExpirationTime.Value > unixNow);
            }
        }

        public void AddClaim(string key, object value)
        {
            if (this.claims.ContainsKey(key))
                throw new ArgumentException("Claim with key " + key + " is already present in the JsonWebToken", nameof(key));

            this.claims[key] = value;
        }

        public void RemoveClaim(string key)
        {
            if (!this.claims.Remove(key))
                throw new KeyNotFoundException("Claim with key " + key + " not found in the JsonWebToken");
        }

        public object FindClaim<TType>(string key)
        {
            object value;

            if (this.claims.TryGetValue(key, out value))
                return (TType)value;

            return default(TType);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.claims.Where(c => c.Value != null).ToDictionary(c => c.Key, c => c.Value));
        }

        private void InitStandardClaims()
        {
            this.claims["iss"] = null;
            this.claims["sub"] = null;
            this.claims["aud"] = new List<string>();
            this.claims["exp"] = null;
            this.claims["nbf"] = null;
            this.claims["iat"] = null;
            this.claims["jti"] = null;
        }
    }
}
