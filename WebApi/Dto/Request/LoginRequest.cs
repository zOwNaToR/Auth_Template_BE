namespace WebApi.Dto;

public class LoginRequest
{
	[Required(ErrorMessage = "Email required")]
	public string? Email { get; set; }

	[Required(ErrorMessage = "Password required")]
	public string? Password { get; set; }
}
