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
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static System.Text.Encoding;

namespace NJose.JsonWebSignature.Algorithms
{
    public abstract class RSAPKCS1Algorithm : IDigitalSignatureAlgorithm
    {
        private readonly string hashAlgorithm;
        private readonly AsymmetricAlgorithm privateKey;
        private AsymmetricAlgorithm publicKey;
        private bool disposePublicKey;
        private bool disposePrivateKey;

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

            this.disposePublicKey = false;
            this.disposePrivateKey = false;

            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        protected RSAPKCS1Algorithm(string hashAlgorithm, CryptographicKey publicKey = null, CryptographicKey privateKey = null)
            : this(hashAlgorithm)
        {
            this.disposePublicKey = true;
            this.disposePrivateKey = true;

            if (publicKey != null)
            {
                this.publicKey = GetAlgorithmFromCryptographicKey(publicKey);

                if (this.publicKey.KeySize < 2048)
                {
                    this.Dispose();
                    throw new ArgumentException("Key size must be at 2048bits");
                }
            }

            if (privateKey != null)
            {
                this.privateKey = GetAlgorithmFromCryptographicKey(privateKey);

                if (this.privateKey.KeySize < 2048)
                {
                    this.Dispose();
                    throw new ArgumentException("Key size must be at 2048bits");
                }
            }
        }

        public virtual string Name { get { throw new NotImplementedException(); } }

        protected bool Disposed { get; private set; }

        /// <summary>
        /// Create a public AsymmetricAlgorithm from CryptographicKey
        /// </summary>
        /// <param name="key"></param>
        public virtual void SetKey(CryptographicKey key)
        {
            this.disposePublicKey = true;

            if (key.X509CertificateChain.Count() > 0)
            {
                // check x509 thumbprint
            }
            else if (key.X509Url != null)
            {
                // check x509 thumbprint
            }
            else
            {
                this.publicKey = GetAlgorithmFromCryptographicKey(key);
            }
        }

        public byte[] Sign(JoseHeader header, string data)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentNullException(nameof(data));
            if (this.privateKey == null)
                throw new InvalidOperationException("Private key not defined");
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(this.privateKey);
            rsaFormatter.SetHashAlgorithm(this.hashAlgorithm);

            return rsaFormatter.CreateSignature(ASCII.GetBytes(data));
        }

        public bool Verify(JoseHeader header, string data, byte[] signature)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            // Get it from header :)
            if (this.publicKey == null)
                this.SetKey(header.GetPublicKey());

            return this.VerifyInternal(header, data, signature);
        }

        public async Task<bool> VerifyAsync(JoseHeader header, string data, byte[] signature)
        {
            if (header == null)
                throw new ArgumentNullException(nameof(header));
            if (this.Disposed)
                throw new ObjectDisposedException(this.GetType().Name);

            // Get it from header :)
            if (this.publicKey == null)
                this.SetKey(await header.GetPublicKeyAsync());

            return this.VerifyInternal(header, data, signature);
        }

        public void Dispose()
        {
            if (this.disposePublicKey)
                this.publicKey?.Dispose();

            if (this.disposePrivateKey)
                this.privateKey?.Dispose();

            this.Dispose(true);
            this.Disposed = true;

            GC.SuppressFinalize(this);
        }

        public bool VerifyInternal(JoseHeader header, string data, byte[] signature)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentNullException(nameof(data));
            if (signature == null || signature.Length == 0)
                throw new ArgumentNullException(nameof(signature));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(this.publicKey);
            rsaDeformatter.SetHashAlgorithm(this.hashAlgorithm);

            return rsaDeformatter.VerifySignature(ASCII.GetBytes(data), signature);
        }

        protected virtual void Dispose(bool disposing)
        {
        }

        private static AsymmetricAlgorithm GetAlgorithmFromCryptographicKey(CryptographicKey key)
        {
            RSAParameters rsaParameters = default(RSAParameters);

            key.TryGetValue("e", out rsaParameters.Modulus);
            key.TryGetValue("n", out rsaParameters.Exponent);
            key.TryGetValue("d", out rsaParameters.D);
            key.TryGetValue("p", out rsaParameters.P);
            key.TryGetValue("q", out rsaParameters.Q);
            key.TryGetValue("dp", out rsaParameters.DP);
            key.TryGetValue("dq", out rsaParameters.DQ);

            var provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaParameters);

            return provider;
        }
    }
}
