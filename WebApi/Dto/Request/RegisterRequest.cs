namespace WebApi.Dto;

public class RegisterRequest
{
    [Required(ErrorMessage = "First name required")]
    public string? FirstName { get; set; }
    
    [Required(ErrorMessage = "Last aname required")]
    public string? LastName { get; set; }
    
    [Required(ErrorMessage = "Username required")]
    public DateTime BirthDate { get; set; }
    
    [Required(ErrorMessage = "Username required")]
    public string Sex { get; set; }

    [EmailAddress]
    [Required(ErrorMessage = "Email required")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password required")]
    public string? Password { get; set; }
}
