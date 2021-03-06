﻿/******************************************************************************
    Copyright 2015 Maxime Degallaix

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
******************************************************************************/

using Newtonsoft.Json;
using System;

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
            if (value == null)
                return null;

            if (value.IndexOf('/') < 0)
                return Prefix + value;
            else
                return value;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (value == null)
                return;

            string strValue = (string)value;

            if (strValue.StartsWith(Prefix) && strValue.IndexOf('/', Prefix.Length + 1) < 0)
                writer.WriteValue(strValue.Remove(0, Prefix.Length));
            else
                writer.WriteValue(strValue);
        }
    }
}
