using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NJose.Test
{
    [TestClass]
    public class JoseHeaderUnitTest
    {
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
