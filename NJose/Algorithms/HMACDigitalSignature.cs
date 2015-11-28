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
using System.Security.Cryptography;

namespace NJose.Algorithms
{
    public abstract class HMACDigitalSignature : IJWADigitalSignature
    {
        protected readonly HMAC hashAlgorithm;
        protected bool disposed;

        public HMACDigitalSignature(HMAC hashAlgorithm)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            this.hashAlgorithm = hashAlgorithm;
            this.disposed = false;
        }

        public virtual string Name { get { throw new NotImplementedException(); } }

        public byte[] Sign(byte[] content)
        {
            if (content == null || content.Length == 0)
                throw new ArgumentNullException(nameof(content));
            if (this.disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            return this.hashAlgorithm.ComputeHash(content);
        }

        public bool Verify(byte[] content, byte[] signature)
        {
            if (content == null || content.Length == 0)
                throw new ArgumentNullException(nameof(content));
            if (signature == null || signature.Length == 0)
                throw new ArgumentNullException(nameof(signature));
            if (this.disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            return this.Sign(content).SequenceEqual(signature);
        }

        public void Dispose()
        {
            this.Dispose(true);
            this.disposed = true;
            
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
        }
    }
}
