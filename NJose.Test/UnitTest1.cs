using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.Algorithms;
using NJose.Extensions;
using NJose.Serialization;

namespace NJose.Test
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.AddClaim("http://example.com/is_root", true);

            var serializer = new JWSCompactSerializer(new HS256DigitalSignature("1To680X8yGFe8wEFu5Ye8bW735CF9j6D"));
            serializer.Serialize(token);

            Assert.Fail(serializer.Serialize(token));
            Assert.AreEqual(
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
                token.ToJson().ToBase64Url());
        }
    }
}
