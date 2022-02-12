namespace DAL.Pocos;

public class ApplicationUser : IdentityUser<Guid>
{
    [Required, MaxLength(256)]
    public string FirstName { get; set; }
    [Required, MaxLength(256)]
    public string LastName { get; set; }
    [Required]
    public DateTime BirthDate { get; set; }
    [MaxLength(1)]
    public string? Sex { get; set; }
    
    public ICollection<RefreshToken> RefreshTokens { get; set; }
}