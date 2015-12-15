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
using System.Text;

namespace NJose.Extensions
{
    internal static class StringExtensions
    {
        private static readonly byte[] EmptyByteArray = new byte[0];

        public static string ToBase64(this string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return string.Empty;

            return Encoding.UTF8.GetBytes(str).ToBase64();
        }

        public static string ToBase64Url(this string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return string.Empty;

            return ToBase64(str).TrimEnd(new[] { '=' });
        }

        public static byte[] FromBase64(this string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return EmptyByteArray;

            return Convert.FromBase64String(str);
        }

        public static byte[] FromBase64Url(this string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return EmptyByteArray;

            // In Base64Url we removed the padding the final '=' characters
            // str must be a multiple of 4
            return FromBase64(str.PadRight(str.Length + 4 - (str.Length % 4), '='));
        }
    }
}
