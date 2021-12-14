namespace WebApi.Dto;

public class AppSettings
{
    public JwtSettings? JWT { get; set; }

}
public class JwtSettings
{
    public string? ValidAudience { get; set; }
    public string? ValidIssuer { get; set; }
    public string? SecretKey { get; set; }
    public int TokenExpiresIn { get; set; }
    public int RefreshTokenExpiresIn { get; set; }
}
