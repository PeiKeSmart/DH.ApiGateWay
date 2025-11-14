using NewLife.Log;
using System.Collections.Concurrent;
using System.Threading;

namespace DH.ApiGateWay.Util;

/// <summary>
/// HTTP请求计数器，用于统计每天通过HttpUtil发起的请求数量
/// </summary>
public static class HttpRequestCounter
{
    // 使用线程安全的字典存储每天的请求数量
    private static readonly ConcurrentDictionary<string, int> _dailyRequestCount = new();

    // 记录上次打印统计数据的小时，用于确保每小时只打印一次
    private static int _lastPrintedHour = -1;

    // 记录上次打印统计数据的日期，用于确保日期变化时也能打印
    private static string _lastPrintedDate = string.Empty;

    /// <summary>
    /// 增加请求计数
    /// </summary>
    /// <param name="method">HTTP方法（仅用于兼容现有API，不实际使用）</param>
    /// <param name="url">请求URL（仅用于兼容现有API，不实际使用）</param>
    public static void IncrementRequestCount(string method, string url)
    {
        DateTime now = DateTime.Now;
        int currentHour = now.Hour;

        // 获取当前日期作为键
        string today = now.ToString("yyyy-MM-dd");

        // 增加日计数
        _dailyRequestCount.AddOrUpdate(today, 1, (_, count) => count + 1);

        // 获取上次打印的日期和小时
        string lastDate = _lastPrintedDate;
        int lastHour = _lastPrintedHour;

        // 检查是否需要打印统计数据（如果小时变化或日期变化）
        bool shouldPrint = lastHour != currentHour || lastDate != today;

        if (shouldPrint)
        {
            // 尝试更新_lastPrintedHour和_lastPrintedDate
            // 只有当前线程是第一个更新的线程时才打印
            if (Interlocked.CompareExchange(ref _lastPrintedHour, currentHour, lastHour) == lastHour)
            {
                // 检查是否是日期变化（新的一天）
                bool isNewDay = lastDate != today && !string.IsNullOrEmpty(lastDate);

                // 更新上次打印的日期
                string previousDate = lastDate;
                Interlocked.Exchange(ref _lastPrintedDate, today);

                // 如果是新的一天的第一个小时（通常是0点），打印前一天的总请求数
                if (isNewDay && currentHour == 0)
                {
                    int yesterdayCount = GetRequestCount(previousDate);
                    XTrace.WriteLine($"[HTTP请求统计] {previousDate} 全天总请求数: {yesterdayCount}");
                }

                // 获取当天的请求总数
                int todayCount = GetRequestCount(today);

                // 打印当天的统计数据
                XTrace.WriteLine($"[HTTP请求统计] {today} 当前总请求数: {todayCount}");
            }
        }
    }

    /// <summary>
    /// 获取指定日期的请求数量
    /// </summary>
    /// <param name="date">日期字符串，格式为yyyy-MM-dd，如果为null则返回今天的数量</param>
    /// <returns>请求数量</returns>
    public static int GetRequestCount(string date = null)
    {
        date ??= DateTime.Now.ToString("yyyy-MM-dd");

        return _dailyRequestCount.TryGetValue(date, out int count) ? count : 0;
    }

    /// <summary>
    /// 获取所有日期的请求统计数据
    /// </summary>
    /// <returns>日期和请求数量的字典</returns>
    public static Dictionary<string, int> GetAllStatistics()
    {
        return _dailyRequestCount.ToDictionary(kv => kv.Key, kv => kv.Value);
    }

    /// <summary>
    /// 打印当天的请求统计数据
    /// </summary>
    public static void PrintTodayStatistics()
    {
        DateTime now = DateTime.Now;
        string today = now.ToString("yyyy-MM-dd");
        int dailyCount = GetRequestCount(today);

        XTrace.WriteLine($"[HTTP请求统计] {today} 当前总请求数: {dailyCount}");
    }

    /// <summary>
    /// 打印所有日期的请求统计数据
    /// </summary>
    public static void PrintAllStatistics()
    {
        var dailyStats = GetAllStatistics();

        XTrace.WriteLine("[HTTP请求统计] 所有统计数据:");

        if (dailyStats.Count == 0)
        {
            XTrace.WriteLine("  暂无请求记录");
            return;
        }

        // 按日期显示
        foreach (var kv in dailyStats.OrderBy(kv => kv.Key))
        {
            XTrace.WriteLine($"  {kv.Key}: {kv.Value} 次请求");
        }

        // 计算总计
        int total = dailyStats.Sum(kv => kv.Value);
        XTrace.WriteLine($"  总计: {total} 次请求");
    }
}
