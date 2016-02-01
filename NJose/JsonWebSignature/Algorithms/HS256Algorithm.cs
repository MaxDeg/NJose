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

using NJose.JsonWebKey;
using System;
using System.Security.Cryptography;
using System.Text;

namespace NJose.JsonWebSignature.Algorithms
{
    public sealed class HS256Algorithm : HMACAlgorithm
    {
        public HS256Algorithm(byte[] key)
            : base(new HMACSHA256(key))
        {
            // key must be larger or equals to 256 bits
            if (key.Length < 256 / 8)
            {
                this.Dispose();
                throw new ArgumentException("A key of the same size as the hash output (256 bits) or larger MUST be used");
            }
        }

        public HS256Algorithm(string key)
            : this(Encoding.UTF8.GetBytes(key)) { }

        public HS256Algorithm(CryptographicKey key)
            : this(GetKey(key)) { }

        public override string Name { get { return "HS256"; } }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
                this.HashAlgorithm?.Dispose();
        }
    }
}
