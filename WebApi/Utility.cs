namespace WebApi;

public static class Utility
{
    public static T? IgnoreErrors<T>(Func<T> function)
    {
        try
        {
            return function();
        }
        catch (Exception)
        {
            return default;
        }
    }
}
