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
using Newtonsoft.Json.Serialization;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace NJose.JsonSerialization
{
    internal sealed class IgnoreEmptyCollectionContractResolver : DefaultContractResolver
    {
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var property = base.CreateProperty(member, memberSerialization);
            var shouldSerialize = property.ShouldSerialize;

            property.ShouldSerialize = obj => (shouldSerialize == null || shouldSerialize(obj)) && this.IsNotEmpty(property, obj);

            return property;
        }

        private bool IsNotEmpty(JsonProperty property, object target)
        {
            var value = property.ValueProvider.GetValue(target) as IEnumerable<object>;
            if (value != null)
                return value.Count() != 0;

            return true;
        }
    }
}
