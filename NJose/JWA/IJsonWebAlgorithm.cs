using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JWA
{
    public interface IJsonWebAlgorithm
    {
        string Name { get; }

        string Sign(byte[] content);
        void Encrypt();
        void Decrypt();
    }
}
