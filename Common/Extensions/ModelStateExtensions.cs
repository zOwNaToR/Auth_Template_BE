using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Common.Extensions;

public static class ModelStateExtensions
{
    public static IEnumerable<string> GetErrors(this ModelStateDictionary ModelState)
    {
        return ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage));
    }
}
