using System.Linq;

namespace Common.Extensions;

public static class LinqExtensions
{
	/// <summary>
	/// Used to modify properties of an object returned from a LINQ query
	/// </summary>
	public static TSource SetProp<TSource>(this TSource input, Action<TSource> updater)
	{
		updater(input);
		return input;
	}

	/// <summary>
	/// Used to modify properties of an object returned from a LINQ query
	/// </summary>
	public static IEnumerable<TElement> SetProp<TElement>(this IEnumerable<TElement> collection, Action<TElement> updater)
	{
		return collection.Select(x =>
		{
			updater(x);
			return x;
		});
	}
}