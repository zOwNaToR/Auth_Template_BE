namespace WebApi.Dto;

public class ResetLinkResponse : BaseResponse
{
    public string? ResetLink { get; set; }
    public string? ResetPasswordToken { get; set; }

    public ResetLinkResponse() { }
    public ResetLinkResponse(bool _success) : base(_success) { }
}
