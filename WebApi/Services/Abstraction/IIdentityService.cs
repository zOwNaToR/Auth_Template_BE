namespace WebApi.Services;
public interface IIdentityService
{
	Task<BaseResponse> RegisterAsync(string username, string email, string password);
	Task<AuthResponse> LoginAsync(string email, string password);
	Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken);
	Task<AuthResponse> RevokeRefreshToken(string token);
	Task<ResetLinkResponse> SendPasswordResetLink(string email);
	Task<BaseResponse> ResetPassword(string email, string password, string resetPasswordToken);
}
