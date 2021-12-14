namespace DAL.Pocos;

public class RefreshToken
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public string Token { get; set; }
    public string JwtId { get; set; } = "";
    public bool Used { get; set; }
    public bool Invalidated { get; set; }

    public DateTime CreationDate { get; set; }
    public DateTime ExpiryDate { get; set; }

    public Guid UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public ApplicationUser User { get; set; }
}
