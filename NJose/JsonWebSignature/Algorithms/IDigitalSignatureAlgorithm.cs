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

using System.Threading.Tasks;

namespace NJose.JsonWebSignature.Algorithms
{
    public interface IDigitalSignatureAlgorithm : IJsonWebAlgorithm
    {
        byte[] Sign(JoseHeader header, string data);

        bool Verify(JoseHeader header, string data, byte[] signature);

        /// <summary>
        /// Async version of Verify should only be used with AsymetricAlgorithm and if JoseHeader contains JWK url or X509 Url
        /// In those 2 cases a http request is done to try to get the public key.
        /// InvalidOperationException is throw with SymetricAlgorithm
        /// </summary>
        /// <param name="header"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        Task<bool> VerifyAsync(JoseHeader header, string data, byte[] signature);
    }
}
