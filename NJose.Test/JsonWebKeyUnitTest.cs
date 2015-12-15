using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Owin.Hosting;
using Owin;
using NJose.JsonWebKey;
using System.Threading.Tasks;

namespace NJose.Test
{
    [TestClass]
    public class JsonWebKeyUnitTest
    {
        private Uri keySetUri = new Uri("http://localhost:3727");
        private IDisposable server;

        [TestInitialize]
        public void Initialize()
        {
            this.server = WebApp.Start(this.keySetUri.ToString(), app => app.Run(c =>
            {
                c.Response.ContentType = "application/json";
                return c.Response.WriteAsync(@"{
                  ""keys"": [
                    {
                      ""alg"": ""HS256"",
                      ""kty"": ""oct"",
                      ""use"": ""sig"",
                      ""k"": ""-AgQASjPKxu1S8Ta4-LxGvAZw9PhkcZkrEhKBw1KzNLnPfW6fwDlsMbrvVplx0nRR4d_GSvbJyx_QVh0XoRMWrZngyJ5MfLxyWkE34F5Eo7rTCCo8xSFr30ecWooJGzDfdN1IS2Liz5dNNknkUWGo40WIz361oeOlb4-LEymuCryt6jG2AFGz0fkNyRgunIU9mrWaBymyKQGj8epEMDmYKCwWILJg-PlBXR2dn5NmRPONozhWY0KVm5Yd5ATcLDsMSSV9ulrVQ1F40uPpPe_DjHxD5aW1t0HHeeiyZ_NRn4HSZIlEtUyh6g6wMasmKPBsSg1o2Fz_bCpsUi23Inx0A"",
                      ""kid"": ""key-1""
                    }
                  ]
                }");
            }));
        }

        [TestCleanup]
        public void Cleanup()
        {
            this.server?.Dispose();
        }

        [TestMethod]
        public async Task Get_Key_By_Id()
        {
            var keySet = await JWKSet.GetAsync(this.keySetUri);
            var key = keySet["key-1"];

            Assert.IsNotNull(key);
            Assert.AreEqual(key.Algorithm, "HS256");
            Assert.AreEqual(key.Use, "sig");
            Assert.AreEqual(key.Type, "oct");

            string value;
            Assert.IsTrue(key.TryGetValue("k", out value));

            Console.Write(value);
        }
    }
}
