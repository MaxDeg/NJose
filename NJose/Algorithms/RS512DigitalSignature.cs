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

using System.Security.Cryptography.X509Certificates;

namespace NJose.Algorithms
{
    public sealed class RS512DigitalSignature : RSAPKCS1DigitalSignature
    {
        public RS512DigitalSignature(X509Certificate2 certificate)
            : base("SHA512", certificate) { }

        public override string Name { get { return "RS512"; } }
    }
}