using System.Globalization;

namespace DH.Iot.Util;

public class DateUtil {
    private const string ISO8601_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    public static string FormatIso8601Date(DateTime date)
    {
        return date.ToUniversalTime().ToString(ISO8601_DATE_FORMAT, CultureInfo.CreateSpecificCulture("en-US"));
    }

    public static string ConvertDateTimeInt(DateTime time)
    {
        DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new DateTime(1970, 1, 1));
        double intResult = (time - startTime).TotalMilliseconds;
        return Convert.ToInt64(intResult).ToString(); ;
    }
}