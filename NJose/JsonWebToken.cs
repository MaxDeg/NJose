using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose
{
    public sealed class JsonWebToken
    {
        private readonly Dictionary<string, object> claims = new Dictionary<string, object>();

        public JsonWebToken()
        {
            this.claims["iss"] = null;
            this.claims["sub"] = null;
            this.claims["aud"] = null;
            this.claims["exp"] = null;
            this.claims["nbf"] = null;
            this.claims["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this.claims["jti"] = Guid.NewGuid().ToString();
        }

        public JsonWebToken(string token)
        {

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

        public string Audience
        {
            get { return (string)this.claims["aud"]; }
            set { this.claims["aud"] = value; }
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
                return true; // TODO
            }
        }

        public void Add(string key, object value)
        {
            if (this.claims.ContainsKey(key))
                throw new ArgumentException("Claim with key " + key + " is already present in the JsonWebToken", nameof(key));

            this.claims[key] = value;
        }

        public void Remove(string key)
        {
            if (!this.claims.Remove(key))
                throw new KeyNotFoundException("Claim with key " + key + " not found in the JsonWebToken");
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.claims.Where(c => c.Value != null).ToDictionary(c => c.Key, c => c.Value));
        }
    }
}
