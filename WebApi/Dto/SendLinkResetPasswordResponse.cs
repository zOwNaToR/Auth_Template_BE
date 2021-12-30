namespace WebApi.Dto;

public class SendLinkResetPasswordResponse : BaseResponse
{
    public string? ResetLink { get; set; }
    public string? ResetPasswordToken { get; set; }

    public SendLinkResetPasswordResponse() { }
    public SendLinkResetPasswordResponse(bool _success) : base(_success) { }
}
