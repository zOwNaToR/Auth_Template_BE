namespace WebApi.Dto;

public class AuthResponse
{
	public bool Success { get; set; }
	public string Token { get; set; } = "";
	public string RefreshToken { get; set; } = "";
	public DateTime ExpireDate { get; set; }
    public bool RefreshTokenHidden { get; set; }

    public string UserName { get; set; } = "";
	public List<string> Roles { get; set; } = new List<string>();
	public List<string> Errors { get; set; } = new List<string>();

	public AuthResponse() { }
	public AuthResponse(bool _success)
	{
		Success = _success;
	}

	public void HideRefreshToken()
    {
		RefreshToken = "";
		RefreshTokenHidden = true;
	}

}

