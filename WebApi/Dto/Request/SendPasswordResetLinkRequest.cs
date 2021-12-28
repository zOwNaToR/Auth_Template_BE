namespace WebApi.Dto;

public class SendPasswordResetLinkRequest
{
    [Required]
    public string Email { get; set; }
}
