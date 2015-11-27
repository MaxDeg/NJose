using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JWA
{
    public interface IJWADigitalSignature : IJsonWebAlgorithm
    {
        string Sign(byte[] content);
    }
}
