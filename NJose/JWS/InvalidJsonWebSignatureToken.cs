using System;
using System.Runtime.Serialization;

namespace NJose.JWS
{
    [Serializable]
    internal class InvalidJsonWebSignatureToken : Exception
    {
        public InvalidJsonWebSignatureToken()
        {
        }

        public InvalidJsonWebSignatureToken(string message) : base(message)
        {
        }

        public InvalidJsonWebSignatureToken(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidJsonWebSignatureToken(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}