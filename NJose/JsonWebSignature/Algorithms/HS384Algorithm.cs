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

using System;
using System.Security.Cryptography;
using System.Text;

namespace NJose.JsonWebSignature.Algorithms
{
    public sealed class HS384Algorithm : HMACAlgorithm
    {
        public HS384Algorithm(byte[] key)
            : base(new HMACSHA384(key))
        {
            // key must be larger or equals to 384 bits
            if (key.Length < 384 / 8)
            {
                this.HashAlgorithm?.Dispose();
                throw new ArgumentException("A key of the same size as the hash output (384 bits) or larger MUST be used");
            }
        }

        public HS384Algorithm(string key)
            : this(Encoding.UTF8.GetBytes(key)) { }

        public override string Name { get { return "HS384"; } }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
                this.HashAlgorithm?.Dispose();
        }
    }
}
