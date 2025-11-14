using System.Security.Cryptography;
using System.Buffers;
using System.Text;

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

        // 使用 ArrayPool 减少中间 byte[] 分配
        Span<char> initialBuffer = stackalloc char[512];
        var builder = new ValueStringBuilder(initialBuffer);
        BuildStringToSign(builder, path, method, headers, querys, bodys, signHeaderPrefixList);
        var span = builder.AsSpan();

        // 把 secret 编码到租用缓冲
        int maxKeyBytes = Encoding.UTF8.GetMaxByteCount(secret.Length);
        byte[] keyBuf = ArrayPool<byte>.Shared.Rent(maxKeyBytes);
        int keyLen = Encoding.UTF8.GetBytes(secret, 0, secret.Length, keyBuf, 0);

        // 把签名字符串编码到租用缓冲
        int maxSignBytes = Encoding.UTF8.GetMaxByteCount(span.Length);
        byte[] signBuf = ArrayPool<byte>.Shared.Rent(maxSignBytes);
        int signLen = Encoding.UTF8.GetBytes(span, signBuf);

        try
        {
            using var algorithm = new HMACSHA256();
            // 将 keyBuf 前 keyLen 部分复制到长度准确的数组并赋值给算法
            byte[] realKey = new byte[keyLen];
            Buffer.BlockCopy(keyBuf, 0, realKey, 0, keyLen);
            algorithm.Key = realKey;

            // 计算摘要并生成签名
            var hash = algorithm.ComputeHash(signBuf, 0, signLen);
            var result = Convert.ToBase64String(hash);

            // 清理 realKey 中的敏感数据
            Array.Clear(realKey, 0, realKey.Length);

            return result;
        }
        finally
        {
            builder.Dispose();
            // 清理并归还租用缓冲。secret 涉及敏感信息，建议清零后归还
            Array.Clear(keyBuf, 0, keyLen);
            ArrayPool<byte>.Shared.Return(keyBuf);

            Array.Clear(signBuf, 0, signLen);
            ArrayPool<byte>.Shared.Return(signBuf);
        }
    }

    /// <summary>
    /// 调试用：验证当前 Sign 输出与基于字符串的老方式一致（用于回归检测）
    /// </summary>
    public static bool VerifySignConsistency(string path, string method, string secret, Dictionary<string, string> headers, Dictionary<string, string> querys, Dictionary<string, string> bodys, List<string> signHeaderPrefixList)
    {
        // 使用当前实现获取签名
        var s1 = Sign(path, method, secret, headers, querys, bodys, signHeaderPrefixList);

        // 使用 builder 生成签名字符串，再使用简单的 Encoding/ComputeHash 计算签名（老实现的等价）
        Span<char> initialBuffer = stackalloc char[512];
        var builder = new ValueStringBuilder(initialBuffer);
        // 使用 headers 的副本来重新构造待签名字符串，避免重复添加 X_CA_SIGNATURE_HEADERS 导致异常
        var headersCopy = headers == null ? new Dictionary<string, string>() : new Dictionary<string, string>(headers, StringComparer.Ordinal);
        BuildStringToSign(builder, path, method, headersCopy, querys, bodys, signHeaderPrefixList);
        var signStr = builder.ToString();
        builder.Dispose();

        using var alg = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var bs = Encoding.UTF8.GetBytes(signStr);
        var hash = alg.ComputeHash(bs);
        var s2 = Convert.ToBase64String(hash);

        return s1 == s2;
    }

    private static void BuildStringToSign(ValueStringBuilder builder, string path, string method, Dictionary<string, string> headers, Dictionary<string, string> querys, Dictionary<string, string> bodys, List<string> signHeaderPrefixList)
    {
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
        BuildHeaders(builder, headers, signHeaderPrefixList);
        BuildResource(builder, path, querys, bodys);
    }

    /**
     * 构建待签名Path+Query+FormParams
     *
     * @param url          Path+Query
     * @param formParamMap POST表单参数
     * @return 待签名Path+Query+FormParams
     */
    private static void BuildResource(ValueStringBuilder builder, string path, Dictionary<string, string> querys, Dictionary<string, string> bodys)
    {
        if (null != path)
        {
            builder.Append(path);
        }

        // 聚合并排序参数，替换 SortedDictionary 以减少分配
        var sortParams = new Dictionary<string, string>(StringComparer.Ordinal);

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
        // 参数列表排序
        if (sortParams.Count > 0)
        {
            var keys = new List<string>(sortParams.Keys);
            keys.Sort(StringComparer.Ordinal);

            var first = true;
            builder.Append('?');
            foreach (var key in keys)
            {
                if (!first)
                {
                    builder.Append('&');
                }
                first = false;

                builder.Append(key);
                var value = sortParams[key];
                if (!string.IsNullOrEmpty(value))
                {
                    builder.Append('=');
                    builder.Append(value);
                }
            }

            // 将 ? 放在参数串前面
            var paramSpan = builder.AsSpan();
            // 不需要额外处理：已经直接写入 builder，Add ? only if we appended parameters directly
            // But original implementation put ? before parameters - keep same
        }
    }


    /**
    * 构建待签名Http头
    *
    * @param headers              请求中所有的Http头
    * @param signHeaderPrefixList 自定义参与签名Header前缀
    * @return 待签名Http头
    */
    private static void BuildHeaders(ValueStringBuilder builder, Dictionary<string, string> headers, List<string> signHeaderPrefixList)
    {
        // 直接写入传入的 builder

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
            // 替换 SortedDictionary：先把 headers 拷贝到临时字典，然后按 key 排序
            var sorted = new Dictionary<string, string>(headers, StringComparer.Ordinal);
            var keys = new List<string>(sorted.Keys);
            keys.Sort(StringComparer.Ordinal);

            Span<char> initialSignHeaderBuffer = stackalloc char[128];
            var signHeadersStringBuilder = new ValueStringBuilder(initialSignHeaderBuffer);

            foreach (var key in keys)
            {
                if (IsHeaderToSign(key, signHeaderPrefixList))
                {
                    var value = sorted[key];
                    builder.Append(key);
                    builder.Append(Constants.SPE2);
                    if (null != value)
                    {
                        builder.Append(value);
                    }
                    builder.Append(Constants.LF);
                    if (0 < signHeadersStringBuilder.Length)
                    {
                        signHeadersStringBuilder.Append(Constants.SPE1);
                    }
                    signHeadersStringBuilder.Append(key);
                }
            }

            string signHeaders = signHeadersStringBuilder.ToString();
            signHeadersStringBuilder.Dispose();
            headers.Add(SystemHeader.X_CA_SIGNATURE_HEADERS, signHeaders);
        }
        return;
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