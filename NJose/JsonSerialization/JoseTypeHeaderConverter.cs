using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose.JsonSerialization
{
    internal sealed class JoseTypeHeaderConverter : JsonConverter
    {
        private const string Prefix = "application/";

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(string);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            string value = reader.Value as string;
            if (value == null) return null;
            
            if (value.IndexOf('/') < 0)
                return Prefix + value;
            else
                return value;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if(value == null) return;

            string strValue = (string)value;

            if (strValue.StartsWith(Prefix) && strValue.IndexOf('/', Prefix.Length + 1) < 0)
                writer.WriteValue(strValue.Remove(0, Prefix.Length));
            else
                writer.WriteValue(strValue);
        }
    }
}
