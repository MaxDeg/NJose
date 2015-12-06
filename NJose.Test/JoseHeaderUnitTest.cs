using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NJose.Test
{
    [TestClass]
    public class JoseHeaderUnitTest
    {
        [TestMethod]
        public void TestMethod1()
        {
            JoseHeader header = new JoseHeader
            {
                JwkSetUrl = new Uri("https://tools.ietf.org/html/rfc7515#section-4.1.9"),
                Type = "application/example",
                ContentType = @"application/example;part=""1/2""",
            };
            header.Add("exp", DateTimeOffset.UtcNow);

            var json = header.ToJson();
            
            Assert.Fail();
        }

        [TestMethod]
        public void Critical_Header_As_List()
        {
            JoseHeader.Parse(@"{ typ: 'example', cty: 'application/example;part=""1/2""', crit: ['test', 'tt'], 'test': 'dsgffgdf', 'tt': '..' }");
        }

        [TestMethod]
        public void Critical_Header_As_String()
        {
            JoseHeader.Parse(@"{ typ: 'example', cty: 'application/example;part=""1/2""', crit: 'test', 'test': 'dsgffgdf' }");
        }
    }
}
