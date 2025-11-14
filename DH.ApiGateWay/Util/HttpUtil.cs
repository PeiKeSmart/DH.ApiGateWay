using DH.Iot.Constant;

using NewLife.Log;
using NewLife.Serialization;

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

using HttpMethod = DH.Iot.Constant.HttpMethod;

namespace DH.Iot.Util;

public class HttpUtil {
    // 静态HttpClient实例，避免每次请求创建新实例导致的端口耗尽问题
    private static readonly HttpClient _httpClient;

    // 静态构造函数，配置HttpClient
    static HttpUtil()
    {
        var handler = new SocketsHttpHandler
        {
            // 启用连接池
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            // 允许最大连接数
            MaxConnectionsPerServer = 400,
            // 启用保持活动连接
            KeepAlivePingPolicy = HttpKeepAlivePingPolicy.WithActiveRequests,
            // 配置SSL证书验证
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = CheckValidationResult
            }
        };

        _httpClient = new HttpClient(handler)
        {
            // 默认超时设置
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    // 异步POST方法
    public static async Task<HttpResponseMessage> HttpPostAsync(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, Dictionary<String, String> bodys, List<String> signHeaderPrefixList, String From)
    {
        return await DoHttpAsync(host, path, HttpMethod.POST, appKey, appSecret, timeout, headers, querys, bodys, signHeaderPrefixList, From).ConfigureAwait(false);
    }

    // 为了保持兼容性的同步POST方法
    public static HttpResponseMessage HttpPost(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, Dictionary<String, String> bodys, List<String> signHeaderPrefixList, String From)
    {
        return DoHttpAsync(host, path, HttpMethod.POST, appKey, appSecret, timeout, headers, querys, bodys, signHeaderPrefixList, From).GetAwaiter().GetResult();
    }

    // 异步PUT方法
    public static async Task<HttpResponseMessage> HttpPutAsync(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, Dictionary<String, String> bodys, List<String> signHeaderPrefixList, String From)
    {
        return await DoHttpAsync(host, path, HttpMethod.PUT, appKey, appSecret, timeout, headers, querys, bodys, signHeaderPrefixList, From).ConfigureAwait(false);
    }

    // 为了保持兼容性的同步PUT方法
    public static HttpResponseMessage HttpPut(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, Dictionary<String, String> bodys, List<String> signHeaderPrefixList, String From)
    {
        return DoHttpAsync(host, path, HttpMethod.PUT, appKey, appSecret, timeout, headers, querys, bodys, signHeaderPrefixList, From).GetAwaiter().GetResult();
    }

    // 异步GET方法
    public static async Task<HttpResponseMessage> HttpGetAsync(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, List<String> signHeaderPrefixList, String From)
    {
        return await DoHttpAsync(host, path, HttpMethod.GET, appKey, appSecret, timeout, headers, querys, null, signHeaderPrefixList, From).ConfigureAwait(false);
    }

    // 为了保持兼容性的同步GET方法
    public static HttpResponseMessage HttpGet(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, List<String> signHeaderPrefixList, String From)
    {
        return DoHttpAsync(host, path, HttpMethod.GET, appKey, appSecret, timeout, headers, querys, null, signHeaderPrefixList, From).GetAwaiter().GetResult();
    }

    // 异步HEAD方法
    public static async Task<HttpResponseMessage> HttpHeadAsync(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, List<String> signHeaderPrefixList, String From)
    {
        return await DoHttpAsync(host, path, HttpMethod.HEAD, appKey, appSecret, timeout, headers, querys, null, signHeaderPrefixList, From).ConfigureAwait(false);
    }

    // 为了保持兼容性的同步HEAD方法
    public static HttpResponseMessage HttpHead(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, List<String> signHeaderPrefixList, String From)
    {
        return DoHttpAsync(host, path, HttpMethod.HEAD, appKey, appSecret, timeout, headers, querys, null, signHeaderPrefixList, From).GetAwaiter().GetResult();
    }

    // 异步DELETE方法
    public static async Task<HttpResponseMessage> HttpDeleteAsync(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, List<String> signHeaderPrefixList, String From)
    {
        return await DoHttpAsync(host, path, HttpMethod.DELETE, appKey, appSecret, timeout, headers, querys, null, signHeaderPrefixList, From).ConfigureAwait(false);
    }

    // 为了保持兼容性的同步DELETE方法
    public static HttpResponseMessage HttpDelete(String host, String path, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, List<String> signHeaderPrefixList, String From)
    {
        return DoHttpAsync(host, path, HttpMethod.DELETE, appKey, appSecret, timeout, headers, querys, null, signHeaderPrefixList, From).GetAwaiter().GetResult();
    }

    // 核心HTTP请求处理方法
    private static async Task<HttpResponseMessage> DoHttpAsync(String host, String path, String method, String appKey, String appSecret, Int32 timeout, Dictionary<String, String> headers, Dictionary<String, String> querys, Dictionary<String, String> bodys, List<String> signHeaderPrefixList, String From)
    {
        // 初始化基本头信息和签名
        headers = InitialBasicHeader(path, appKey, appSecret, method, headers, querys, bodys, signHeaderPrefixList);

        // 构建URL
        String url = BuildUrl(host, path, querys);

        // 增加请求计数
        HttpRequestCounter.IncrementRequestCount(method, url);

        // 创建请求消息
        var request = new HttpRequestMessage
        {
            // 设置请求方法
            Method = ConvertToSystemHttpMethod(method),

            // 设置请求URI
            RequestUri = new Uri(url)
        };

        // 设置请求头
        foreach (var header in headers)
        {
            // 跳过特殊处理的头
            if (header.Key == "Accept" || header.Key == "Date" || header.Key == HttpHeader.HTTP_HEADER_CONTENT_TYPE)
                continue;

            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        // 设置Accept头
        if (headers.TryGetValue("Accept", out string accept))
        {
            request.Headers.Accept.ParseAdd(accept);
        }

        // 设置Date头
        if (headers.TryGetValue("Date", out string date))
        {
            request.Headers.Date = Convert.ToDateTime(date);
        }

        // 处理请求体
        if (bodys != null && bodys.Count > 0)
        {
            string bodyContent = BuildParameterString(bodys);

            // 创建内容
            var content = new StringContent(bodyContent, Encoding.UTF8);

            // 修改这部分代码：处理 Content-Type
            if (headers.TryGetValue(HttpHeader.HTTP_HEADER_CONTENT_TYPE, out string contentTypeValue))
            {

                // 解析 Content-Type
                String mediaType = contentTypeValue;
                String charset = null;

                // 如果包含分号，需要分离媒体类型和字符集
                if (contentTypeValue.Contains(';'))
                {
                    var parts = contentTypeValue.Split([';'], 2);
                    mediaType = parts[0].Trim();

                    // 如果有字符集参数
                    if (parts.Length > 1 && parts[1].Trim().StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
                    {
                        charset = parts[1].Trim()[8..].Trim('\"', '\'');
                    }
                }

                // 设置 Content-Type 的 MediaType 部分
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mediaType);

                // 如果有字符集，则设置
                if (!String.IsNullOrEmpty(charset))
                {
                    content.Headers.ContentType.CharSet = charset;
                }
            }

            // 添加对Content-MD5头的处理
            if (headers.TryGetValue(HttpHeader.HTTP_HEADER_CONTENT_MD5, out string value))
            {
                content.Headers.Add(HttpHeader.HTTP_HEADER_CONTENT_MD5, value);
            }

            request.Content = content;
        }

        // 设置超时
        var timeoutTokenSource = new System.Threading.CancellationTokenSource(TimeSpan.FromMilliseconds(timeout));

        try
        {
            // 发送请求并获取响应
            return await _httpClient.SendAsync(request, timeoutTokenSource.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // 记录错误日志
            var requestInfo = new
            {
                Host = host,
                Path = path,
                Method = method,
                Url = url,
                Headers = headers,
                Timeout = timeout
            };

            XTrace.WriteLine($"请求网关出错时传输的数据：{From}_{requestInfo.ToJson()}");
            XTrace.WriteException(ex);

            // 创建错误响应
            var errorResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent($"请求发生错误: {ex.Message}")
            };

            return errorResponse;
        }
    }

    // 构建完整URL
    private static String BuildUrl(String host, String path, Dictionary<String, String> querys)
    {
        String url = host;
        if (path != null)
        {
            url += path;
        }

        string queryString = BuildParameterString(querys);
        if (!string.IsNullOrEmpty(queryString))
        {
            url = string.Concat(url, "?", queryString);
        }

        return url;
    }

    // 将自定义HttpMethod转换为系统HttpMethod
    private static System.Net.Http.HttpMethod ConvertToSystemHttpMethod(String method)
    {
        return method switch
        {
            HttpMethod.GET => System.Net.Http.HttpMethod.Get,
            HttpMethod.POST => System.Net.Http.HttpMethod.Post,
            HttpMethod.PUT => System.Net.Http.HttpMethod.Put,
            HttpMethod.DELETE => System.Net.Http.HttpMethod.Delete,
            HttpMethod.HEAD => System.Net.Http.HttpMethod.Head,
            _ => System.Net.Http.HttpMethod.Get,
        };
    }

    // 初始化基本请求头和签名（保持原有逻辑不变）
    private static Dictionary<String, String> InitialBasicHeader(String path, String appKey, String appSecret, String method, Dictionary<String, String> headers, Dictionary<String, String> querys, Dictionary<String, String> bodys, List<String> signHeaderPrefixList)
    {
        headers ??= [];

        //时间戳
        headers.Add(SystemHeader.X_CA_TIMESTAMP, DateUtil.ConvertDateTimeInt(DateTime.Now).ToString());
        //防重放，协议层不能进行重试，否则会报NONCE被使用；如果需要协议层重试，请注释此行
        headers.Add(SystemHeader.X_CA_NONCE, Guid.NewGuid().ToString());
        headers.Add(SystemHeader.X_CA_KEY, appKey);
        headers.Add(SystemHeader.X_CA_SIGNATURE, SignUtil.Sign(path, method, appSecret, headers, querys, bodys, signHeaderPrefixList));

        return headers;
    }

    // SSL证书验证回调（保持原有逻辑不变）
    public static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
    {
        return true;
    }

    private static string BuildParameterString(Dictionary<String, String>? parameters)
    {
        if (parameters == null || parameters.Count == 0)
        {
            return string.Empty;
        }

        Span<char> initialBuffer = stackalloc char[256];
        var builder = new ValueStringBuilder(initialBuffer);

        foreach (var param in parameters)
        {
            if (builder.Length > 0)
            {
                builder.Append('&');
            }

            if (param.Value != null && param.Key == null)
            {
                builder.Append(param.Value);
                continue;
            }

            if (param.Key != null)
            {
                if (param.Key.Length == 0)
                {
                    if (param.Value != null)
                    {
                        builder.Append(param.Value);
                    }
                    continue;
                }

                builder.Append(param.Key);
                builder.Append('=');
                if (param.Value != null)
                {
                    builder.Append(HttpUtility.UrlEncode(param.Value, Encoding.UTF8));
                }
            }
        }

        string result = builder.ToString();
        builder.Dispose();
        return result;
    }
}