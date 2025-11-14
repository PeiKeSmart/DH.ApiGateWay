using System.Security.Cryptography;
using System.Text;
using System.Buffers;

using DH.ApiGateWay.Constant;

namespace DH.ApiGateWay.Util;

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

        // 生成签名字符串（保持原有逻辑和顺序）
        string signStr = BuildStringToSign(path, method, headers, querys, bodys, signHeaderPrefixList);

        // 将 secret 编码为字节（最小侵入：保留使用 exact-length key）
        int maxKeyBytes = Encoding.UTF8.GetMaxByteCount(secret.Length);
        byte[] rentedKey = ArrayPool<byte>.Shared.Rent(maxKeyBytes);
        int keyLen = Encoding.UTF8.GetBytes(secret, 0, secret.Length, rentedKey, 0);
        byte[] realKey = new byte[keyLen];
        Buffer.BlockCopy(rentedKey, 0, realKey, 0, keyLen);

        // 把签名字符串编码到租用缓冲，避免新分配数组
        int maxSignBytes = Encoding.UTF8.GetMaxByteCount(signStr.Length);
        byte[] rentedSign = ArrayPool<byte>.Shared.Rent(maxSignBytes);
        int signLen = Encoding.UTF8.GetBytes(signStr, 0, signStr.Length, rentedSign, 0);

        try
        {
            using var algorithm = new HMACSHA256(realKey);
            var hash = algorithm.ComputeHash(rentedSign, 0, signLen);
            return Convert.ToBase64String(hash);
        }
        finally
        {
            // 清理并归还缓冲
            Array.Clear(rentedKey, 0, keyLen);
            ArrayPool<byte>.Shared.Return(rentedKey);

            Array.Clear(rentedSign, 0, signLen);
            ArrayPool<byte>.Shared.Return(rentedSign);
            Array.Clear(realKey, 0, realKey.Length);
        }
    }

    private static string BuildStringToSign(string path, string method, Dictionary<string, string> headers, Dictionary<string, string> querys, Dictionary<string, string> bodys, List<string> signHeaderPrefixList)
    {
        Span<char> initialBuffer = stackalloc char[512];
        var builder = new ValueStringBuilder(initialBuffer);

        builder.Append(method.ToUpper());
        builder.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_ACCEPT) && headers[HttpHeader.HTTP_HEADER_ACCEPT] != null)
        {
            builder.Append(headers[HttpHeader.HTTP_HEADER_ACCEPT]);
        }
        builder.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_CONTENT_MD5) && headers[HttpHeader.HTTP_HEADER_CONTENT_MD5] != null)
        {
            builder.Append(headers[HttpHeader.HTTP_HEADER_CONTENT_MD5]);
        }
        builder.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_CONTENT_TYPE) && headers[HttpHeader.HTTP_HEADER_CONTENT_TYPE] != null)
        {
            builder.Append(headers[HttpHeader.HTTP_HEADER_CONTENT_TYPE]);
        }
        builder.Append(Constants.LF);
        if (headers.ContainsKey(HttpHeader.HTTP_HEADER_DATE) && headers[HttpHeader.HTTP_HEADER_DATE] != null)
        {
            builder.Append(headers[HttpHeader.HTTP_HEADER_DATE]);
        }
        builder.Append(Constants.LF);
        builder.Append(BuildHeaders(headers, signHeaderPrefixList));
        builder.Append(BuildResource(path, querys, bodys));

        string result = builder.ToString();
        builder.Dispose();
        return result;
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
        Span<char> initialBuffer = stackalloc char[256];
        var builder = new ValueStringBuilder(initialBuffer);
        if (null != path)
        {
            builder.Append(path);
        }
        Span<char> initialParamBuffer = stackalloc char[256];
        var paramBuilder = new ValueStringBuilder(initialParamBuffer);
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
                if (0 < paramBuilder.Length)
                {
                    paramBuilder.Append("&");
                }
                paramBuilder.Append(param.Key);
                if (!string.IsNullOrEmpty(param.Value))
                {
                    paramBuilder.Append('=');
                    paramBuilder.Append(param.Value);
                }
            }
        }
        var paramSpan = paramBuilder.AsSpan();
        if (paramSpan.Length > 0)
        {
            builder.Append('?');
            builder.Append(paramSpan);
        }

        string result = builder.ToString();
        paramBuilder.Dispose();
        builder.Dispose();
        return result;
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
        Span<char> initialHeaderBuffer = stackalloc char[256];
        var sb = new ValueStringBuilder(initialHeaderBuffer);

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
            Span<char> initialSignHeaderBuffer = stackalloc char[128];
            var signHeadersStringBuilder = new ValueStringBuilder(initialSignHeaderBuffer);

            foreach (var param in sortedParams)
            {
                if (IsHeaderToSign(param.Key, signHeaderPrefixList))
                {
                    sb.Append(param.Key);
                    sb.Append(Constants.SPE2);
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

            string signHeaders = signHeadersStringBuilder.ToString();
            signHeadersStringBuilder.Dispose();
            headers.Add(SystemHeader.X_CA_SIGNATURE_HEADERS, signHeaders);
        }
        string result = sb.ToString();
        sb.Dispose();
        return result;
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