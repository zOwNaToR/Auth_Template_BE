namespace WebApi.Dto;

public class ConfirmEmailRequest
{
    [Required]
    public Guid UserId { get; set; }

    [Required]
    public string Token { get; set; }
}
