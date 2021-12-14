namespace WebApi.Services;
public interface IIdentityService
{
	Task<AuthResponse> RegisterAsync(string username, string email, string password);
	Task<AuthResponse> LoginAsync(string email, string password);
	Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken);
	Task<AuthResponse> RevokeRefreshToken(string token);
}
