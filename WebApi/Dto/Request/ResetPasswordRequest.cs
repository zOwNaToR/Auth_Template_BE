namespace WebApi.Dto;

public class ResetPasswordRequest
{
    [Required]
    public Guid UserId { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    public string Token { get; set; }
}
