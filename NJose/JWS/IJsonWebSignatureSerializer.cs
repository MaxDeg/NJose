using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JWS
{
    public interface IJsonWebSignatureSerializer
    {
        string Serialize(JsonWebToken token);
        JsonWebToken Deserialize(string token);
    }
}
