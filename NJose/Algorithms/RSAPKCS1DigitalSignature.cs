﻿/******************************************************************************
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
using System.Security.Cryptography.X509Certificates;

namespace NJose.Algorithms
{
    public abstract class RSAPKCS1DigitalSignature : IJWADigitalSignature
    {
        private readonly string hashAlgorithm;
        private readonly AsymmetricAlgorithm publicKey;
        private readonly AsymmetricAlgorithm privateKey;

        public RSAPKCS1DigitalSignature(string hashAlgorithm, X509Certificate2 certificate)
        {
            this.hashAlgorithm = hashAlgorithm;

            if (!certificate.HasPrivateKey)
                throw new ArgumentException("Private key not defined");

            this.publicKey = certificate.PublicKey.Key;
            this.privateKey = certificate.PrivateKey;
        }

        public virtual string Name { get { throw new NotImplementedException(); } }
        
        public byte[] Sign(byte[] content)
        {
            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(this.privateKey);
            rsaFormatter.SetHashAlgorithm(this.hashAlgorithm);

            return rsaFormatter.CreateSignature(content);
        }

        public bool Verify(byte[] content, byte[] signature)
        {
            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(this.publicKey);
            rsaDeformatter.SetHashAlgorithm(this.hashAlgorithm);

            return rsaDeformatter.VerifySignature(content, signature);
        }

        public void Dispose() { }
    }
}