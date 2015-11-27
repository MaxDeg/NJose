using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JWA
{
    public sealed class NoneDigitalSignature : IJWADigitalSignature
    {
        public string Name { get { return "none"; } }

        public string Sign(byte[] content)
        {
            // No signature for this algorithm type ;)
            return null;
        }
    }
}
