using NJose.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NJose.Test
{
    [TestClass]
    public class Base64UnitTest
    {
        [TestMethod]
        public void Test_Base64UrlEncode()
        {
            var encodedStr = "CYftCarwwGQAURMOsKTAgi7g_lNkHMhra3mEe4cOL91kOvrveANQyAXhcJW82dzVSH_GvHE_C_A630YQmnV-7G4PWQdKY1RPOxLhNGRWS9EHSeySoOhAaVJ4DzvXZ6lcqlXTj3wEpFQo07NYGqLovNh3H0TQwmLT6mT-JSXMfviAMz4zFkesKreG68Z9K-Kg4JHbb9fydNyyY339OKsnrhtS1k-RHp3iitXmINfzLEKZIU38T3BIt6mRvTjWCClvAhJQCTMztAoUFeIu_MSGaFBHj3Wd4_tY0A3Hg6zQJro-3IPQrX1M1J_YKR2NRE1Er2C_aFCMcLx4pyUhF88wAQ";
            var decoded = encodedStr.FromBase64Url();
            var reEncoded = decoded.ToBase64Url();

            Assert.AreEqual(encodedStr, reEncoded);
        }
    }
}
