namespace WebApi.Services;

public class UserService: IUserService
{
	private readonly HttpContext _httpContext;
	private readonly AppDbContext _dbContext;

	public UserService(AppDbContext dbContext,
		IHttpContextAccessor httpContextAccessor
	)
	{
		_dbContext = dbContext;
		_httpContext = httpContextAccessor!.HttpContext!;
	}

	public Guid GetUserId() => Guid.Parse(_httpContext.User!.Claims!.First(x => x.Type == Constants.CustomClaimTypes.Id).Value);
	public async Task<ApplicationUser?> GetUserByIdAsync(Guid userId) => await _dbContext.Users.FirstOrDefaultAsync(x => x.Id == userId);
	public async Task<ApplicationUser?> GetCurrentUserAsync() => await GetUserByIdAsync(GetUserId());
}
