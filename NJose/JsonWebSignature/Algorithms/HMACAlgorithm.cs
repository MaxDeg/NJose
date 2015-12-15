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

using NJose.Extensions;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static System.Text.Encoding;

namespace NJose.JsonWebSignature.Algorithms
{
    public abstract class HMACAlgorithm : IDigitalSignatureAlgorithm
    {
        private readonly HMAC hashAlgorithm;

        protected HMACAlgorithm(HMAC hashAlgorithm)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            this.hashAlgorithm = hashAlgorithm;
            this.Disposed = false;
        }

        public virtual string Name { get { throw new NotImplementedException(); } }

        protected bool Disposed { get; private set; }

        protected HMAC HashAlgorithm { get { return this.hashAlgorithm; } }

        public byte[] Sign(JoseHeader header, string payload)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (string.IsNullOrWhiteSpace(payload))
                throw new ArgumentNullException(nameof(payload));
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            var contentToSign = string.Join(".", header.ToJson().ToBase64Url(), payload.ToBase64Url());
            return this.HashAlgorithm.ComputeHash(ASCII.GetBytes(contentToSign));
        }

        public bool Verify(JoseHeader header, string payload, byte[] signature)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (string.IsNullOrWhiteSpace(payload))
                throw new ArgumentNullException(nameof(payload));
            if (signature == null || signature.Length == 0)
                throw new ArgumentNullException(nameof(signature));
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            return this.Sign(header, payload).SequenceEqual(signature);
        }

        public Task<bool> VerifyAsync(JoseHeader header, string payload, byte[] signature)
        {
            throw new InvalidOperationException();
        }

        public void Dispose()
        {
            this.Dispose(true);
            this.Disposed = true;

            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
        }
    }
}
