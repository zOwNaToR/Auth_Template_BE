namespace WebApi.Services;
public interface IIdentityService
{
	Task<BaseResponse> RegisterAsync(RegisterRequest request);
	Task<BaseResponse> RegisterAsync(string email, string password, string firstName, string lastName, DateTime birthDate, string sex);
	Task<AuthResponse> LoginAsync(string email, string password);
	Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken);
	Task<AuthResponse> RevokeRefreshTokenAsync(string token);
	Task<SendLinkResetPasswordResponse> SendPasswordResetLinkAsync(string email);
	Task<BaseResponse> ResetPasswordAsync(Guid userId, string password, string resetPasswordToken);
	Task<BaseResponse> ConfirmEmailAsync(Guid userId, string confirmEmailToken);
}
