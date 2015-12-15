using System;
using System.Runtime.Serialization;

namespace NJose
{
    [Serializable]
    internal class InvalidJoseHeaderException : Exception
    {
        public InvalidJoseHeaderException()
        {
        }

        public InvalidJoseHeaderException(string headerKey)
            : base("invalid header " + headerKey)
        {
        }
    }
}