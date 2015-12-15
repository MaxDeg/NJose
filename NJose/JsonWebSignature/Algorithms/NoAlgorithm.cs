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
using System.Linq;
using System.Threading.Tasks;

namespace NJose.JsonWebSignature.Algorithms
{
    internal sealed class NoAlgorithm : IDigitalSignatureAlgorithm
    {
        private static readonly byte[] EmptyByteArray = new byte[0];

        private bool disposed = false;

        public string Name { get { return "none"; } }

        public byte[] Sign(JoseHeader header, string payload)
        {
            // No signature for this algorithm type ;)
            return EmptyByteArray;
        }

        public bool Verify(JoseHeader header, string payload, byte[] signature)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            if (this.disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            return EmptyByteArray.SequenceEqual(signature);
        }

        public Task<bool> VerifyAsync(JoseHeader header, string payload, byte[] signature)
        {
            throw new InvalidOperationException();
        }

        public void Dispose()
        {
            this.disposed = true;
        }
    }
}
