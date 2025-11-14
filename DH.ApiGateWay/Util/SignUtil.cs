using DH.Iot.Constant;

using System.Security.Cryptography;
using System.Text;

namespace DH.Iot.Util;

public class SignUtil {
    public static string Sign(string path, string method, string secret, Dictionary<string, string> headers, Dictionary<string, string> querys, Dictionary<string, string> bodys, List<string> signHeaderPrefixList)
    {
        //XTrace.WriteLine($"Sign数据Path:{path}");
        //XTrace.WriteLine($"Sign数据Method:{method}");
        //XTrace.WriteLine($"Sign数据Secret:{secret}");
        //foreach (var item in headers)
        //{
        //    XTrace.WriteLine($"Sign数据Headers:{item.Key}:{item.Value}");
        //}
        //foreach (var item in querys)
        //{
        //    XTrace.WriteLine($"Sign数据Querys:{item.Key}:{item.Value}");
        //}
        //foreach (var item in bodys)
        //{
        //    XTrace.WriteLine($"Sign数据Bodys:{item.Key}:{item.Value}");
        //}
        //foreach (var item in signHeaderPrefixList)
        //{
        //    XTrace.WriteLine($"Sign数据SignHeaderPrefixList:{item}");
        //}

        using var algorithm = new HMACSHA256();
        algorithm.Key = Encoding.UTF8.GetBytes(secret.ToCharArray());
        string signStr = BuildStringToSign(path, method, headers, querys, bodys, signHeaderPrefixList);
        return Convert.ToBase64String(algorithm.ComputeHash(Encoding.UTF8.GetBytes(signStr.ToCharArray())));
    }

    private static string BuildStringToSign(string path, string method, Dictionary<string, string> headers, Dictionary<string, string> querys, Dictionary<string, string> bodys, List<string> signHeaderPrefixList)
    {
        StringBuilder sb = new StringBuilder();

        sb.Append(method.ToUpper()).Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_ACCEPT) && headers[HttpHeader.HTTP_HEADER_ACCEPT] != null)
        {
            sb.Append(headers[HttpHeader.HTTP_HEADER_ACCEPT]);
        }
        sb.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_CONTENT_MD5) && headers[HttpHeader.HTTP_HEADER_CONTENT_MD5] != null)
        {
            sb.Append(headers[HttpHeader.HTTP_HEADER_CONTENT_MD5]);
        }
        sb.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_CONTENT_TYPE) && headers[HttpHeader.HTTP_HEADER_CONTENT_TYPE] != null)
        {
            sb.Append(headers[HttpHeader.HTTP_HEADER_CONTENT_TYPE]);
        }
        sb.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_DATE) && headers[HttpHeader.HTTP_HEADER_DATE] != null)
        {
            sb.Append(headers[HttpHeader.HTTP_HEADER_DATE]);
        }
        sb.Append(Constants.LF);
        sb.Append(BuildHeaders(headers, signHeaderPrefixList));
        sb.Append(BuildResource(path, querys, bodys));

        return sb.ToString();
    }

    /**
     * 构建待签名Path+Query+FormParams
     *
     * @param url          Path+Query
     * @param formParamMap POST表单参数
     * @return 待签名Path+Query+FormParams
     */
    private static string BuildResource(string path, Dictionary<string, string> querys, Dictionary<string, string> bodys)
    {
        StringBuilder sb = new StringBuilder();
        if (null != path)
        {
            sb.Append(path);
        }
        StringBuilder sbParam = new StringBuilder();
        IDictionary<string, string> sortParams = new SortedDictionary<string, string>(StringComparer.Ordinal);

        //query参与签名
        if (querys != null && querys.Count > 0)
        {
            foreach (var param in querys)
            {
                if (0 < param.Key.Length)
                {
                    sortParams.Add(param.Key, param.Value);
                }
            }
        }

        //body参与签名
        if (bodys != null && bodys.Count > 0)
        {
            foreach (var param in bodys)
            {
                if (0 < param.Key.Length)
                {
                    sortParams.Add(param.Key, param.Value);
                }
            }
        }
        //参数Key           
        foreach (var param in sortParams)
        {
            if (0 < param.Key.Length)
            {
                if (0 < sbParam.Length)
                {
                    sbParam.Append("&");
                }
                sbParam.Append(param.Key);
                if (!string.IsNullOrEmpty(param.Value))
                {
                    sbParam.Append("=").Append(param.Value);
                }
            }
        }
        if (0 < sbParam.Length)
        {
            sb.Append("?").Append(sbParam);
        }

        return sb.ToString();
    }


    /**
    * 构建待签名Http头
    *
    * @param headers              请求中所有的Http头
    * @param signHeaderPrefixList 自定义参与签名Header前缀
    * @return 待签名Http头
    */
    private static string BuildHeaders(Dictionary<string, string> headers, List<string> signHeaderPrefixList)
    {
        StringBuilder sb = new StringBuilder();

        if (null != signHeaderPrefixList)
        {
            //剔除X-Ca-Signature/X-Ca-Signature-Headers/Accept/Content-MD5/Content-Type/Date
            signHeaderPrefixList.Remove("X-Ca-Signature");
            signHeaderPrefixList.Remove("X-Ca-Signature-Headers");
            signHeaderPrefixList.Remove("Accept");
            signHeaderPrefixList.Remove("Content-MD5");
            signHeaderPrefixList.Remove("Content-Type");
            signHeaderPrefixList.Remove("Date");
            signHeaderPrefixList.Sort(StringComparer.Ordinal);
        }

        //Dictionary<String, String> headersToSign = new Dictionary<String, String>();            
        if (null != headers)
        {
            IDictionary<string, string> sortedParams = new SortedDictionary<string, string>(headers, StringComparer.Ordinal);
            StringBuilder signHeadersStringBuilder = new StringBuilder();

            foreach (var param in sortedParams)
            {
                if (IsHeaderToSign(param.Key, signHeaderPrefixList))
                {
                    sb.Append(param.Key).Append(Constants.SPE2);
                    if (null != param.Value)
                    {
                        sb.Append(param.Value);
                    }
                    sb.Append(Constants.LF);
                    if (0 < signHeadersStringBuilder.Length)
                    {
                        signHeadersStringBuilder.Append(Constants.SPE1);
                    }
                    signHeadersStringBuilder.Append(param.Key);
                }
            }

            headers.Add(SystemHeader.X_CA_SIGNATURE_HEADERS, signHeadersStringBuilder.ToString());
        }

        return sb.ToString();
    }


    /**
    * Http头是否参与签名
    * return
    */
    private static bool IsHeaderToSign(string headerName, List<string> signHeaderPrefixList)
    {
        if (string.IsNullOrEmpty(headerName))
        {
            return false;
        }

        if (headerName.StartsWith(Constants.CA_HEADER_TO_SIGN_PREFIX_SYSTEM))
        {
            return true;
        }

        if (signHeaderPrefixList != null)
        {
            foreach (var signHeaderPrefix in signHeaderPrefixList)
            {
                if (headerName.StartsWith(signHeaderPrefix))
                {
                    return true;
                }
            }
        }

        return false;
    }
}