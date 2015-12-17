using Microsoft.Owin.Hosting;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NJose.JsonWebKey;
using Owin;
using System;
using System.IO;
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
            var content = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keyset.json"));

            this.server = WebApp.Start(this.keySetUri.ToString(), app => app.Run(c =>
            {
                c.Response.ContentType = "application/json";
                return c.Response.WriteAsync(content);
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
            var key = keySet["hs-256"];

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
