﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NJose.Test
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var token = new JsonWebToken { Issuer = "joe", ExpirationTime = 1300819380 };
            token.Add("http://example.com/is_root", true);

            Assert.AreEqual(
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
                token.ToJson().ToBase64Url());
        }
    }
}
