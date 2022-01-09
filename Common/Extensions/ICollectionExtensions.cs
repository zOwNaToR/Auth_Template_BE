namespace Common.Extensions;

public static class ICollectionExtensions
{
	public static void AddRange<T>(this ICollection<T> colletions, IEnumerable<T> elementsToAdd)
	{
		foreach (T element in elementsToAdd)
		{
			colletions.Add(element);
		}
	}
}