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
using NJose.JsonWebKey;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static System.Text.Encoding;

namespace NJose.JsonWebSignature.Algorithms
{
    public abstract class RSAPKCS1Algorithm : IDigitalSignatureAlgorithm
    {
        private readonly string hashAlgorithm;
        private readonly AsymmetricAlgorithm privateKey;
        private readonly AsymmetricAlgorithm publicKey;

        protected RSAPKCS1Algorithm(string hashAlgorithm)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            this.hashAlgorithm = hashAlgorithm;
            this.Disposed = false;
        }

        protected RSAPKCS1Algorithm(string hashAlgorithm, AsymmetricAlgorithm publicKey = null, AsymmetricAlgorithm privateKey = null)
            : this(hashAlgorithm)
        {
            if (publicKey.KeySize < 2048)
                throw new ArgumentException("Key size must be at 2048bits");
            if (privateKey.KeySize < 2048)
                throw new ArgumentException("Key size must be at 2048bits");

            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public virtual string Name { get { throw new NotImplementedException(); } }

        protected bool Disposed { get; private set; }

        /// <summary>
        /// Create a public AsymmetricAlgorithm from CryptographicKey
        /// </summary>
        /// <param name="key"></param>
        public virtual void SetKey(CryptographicKey key)
        {
            if (key.X509CertificateChain.Count > 0)
            {
                // check x509 thumbprint
            }
            else if (key.X509Url != null)
            {
                // check x509 thumbprint
            }
        }

        public byte[] Sign(JoseHeader header, string payload)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (string.IsNullOrWhiteSpace(payload))
                throw new ArgumentNullException(nameof(payload));
            if (this.privateKey == null)
                throw new InvalidOperationException("Private key not defined");
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(this.privateKey);
            rsaFormatter.SetHashAlgorithm(this.hashAlgorithm);

            var contentToSign = string.Join(".", header.ToJson().ToBase64Url(), payload.ToBase64Url());
            return rsaFormatter.CreateSignature(ASCII.GetBytes(contentToSign));
        }

        public bool Verify(JoseHeader header, string payload, byte[] signature)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            // Get it from header :)
            if (this.publicKey == null)
                this.SetKey(header.GetPublicKey());

            return this.VerifyInternal(header, payload, signature);
        }

        public async Task<bool> VerifyAsync(JoseHeader header, string payload, byte[] signature)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            // Get it from header :)
            if (this.publicKey == null)
                this.SetKey(await header.GetPublicKeyAsync());

            return this.VerifyInternal(header, payload, signature);
        }

        public void Dispose()
        {
            this.Disposed = true;
        }

        public bool VerifyInternal(JoseHeader header, string payload, byte[] signature)
        {
            if (string.IsNullOrWhiteSpace(payload))
                throw new ArgumentNullException(nameof(payload));
            if (signature == null || signature.Length == 0)
                throw new ArgumentNullException(nameof(signature));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(this.publicKey);
            rsaDeformatter.SetHashAlgorithm(this.hashAlgorithm);

            var contentToSign = string.Join(".", header.ToJson().ToBase64Url(), payload.ToBase64Url());
            return rsaDeformatter.VerifySignature(ASCII.GetBytes(contentToSign), signature);
        }
    }
}
