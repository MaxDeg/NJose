using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose
{
    internal sealed class JoseHeader
    {
        private readonly Dictionary<string, object> headers = new Dictionary<string, object>();

        public JoseHeader()
        {
            this.headers["typ"] = "JWT";
            this.headers["alg"] = null;
        }

        public JoseHeader(string token)
        {

        }

        // typ
        public string Type { get { return (string)this.headers["typ"]; } }

        public string Algorithm
        {
            get { return (string)this.headers["alg"]; }
            set { this.headers["alg"] = value; }
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.headers.Where(c => c.Value != null).ToDictionary(c => c.Key, c => c.Value));
        }
    }
}
