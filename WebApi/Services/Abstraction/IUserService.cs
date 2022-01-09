namespace WebApi.Services;

public interface IUserService
{
	Guid GetUserId();
	Task<ApplicationUser?> GetUserByIdAsync(Guid userId);
	Task<ApplicationUser?> GetCurrentUserAsync();
}
