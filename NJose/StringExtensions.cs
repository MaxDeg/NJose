using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NJose
{
    internal static class StringExtensions
    {
        public static string ToBase64(this string str)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(str));
        }

        public static string ToBase64Url(this string str)
        {
            return ToBase64(str).TrimEnd(new[] { '=' });
        }
    }
}
