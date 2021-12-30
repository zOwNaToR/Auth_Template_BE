namespace WebApi.Services;
public interface IIdentityService
{
	Task<BaseResponse> RegisterAsync(string username, string email, string password);
	Task<AuthResponse> LoginAsync(string email, string password);
	Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken);
	Task<AuthResponse> RevokeRefreshTokenAsync(string token);
	Task<SendLinkResetPasswordResponse> SendPasswordResetLinkAsync(string email);
	Task<BaseResponse> ResetPasswordAsync(Guid userId, string password, string resetPasswordToken);
	Task<BaseResponse> ConfirmEmailAsync(Guid userId, string confirmEmailToken);
}
