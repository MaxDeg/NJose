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

namespace NJose.Extensions
{
    internal static class ByteArrayExtensions
    {
        public static string ToBase64(this byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0)
                return string.Empty;

            return Convert.ToBase64String(buffer);
        }

        public static string ToBase64Url(this byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0)
                return string.Empty;

            return ToBase64(buffer).TrimEnd(new[] { '=' });
        }
    }
}
