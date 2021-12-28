namespace WebApi.Dto;

public class BaseResponse
{
	public bool Success { get; set; }
	public List<string> Errors { get; set; } = new List<string>();

    public BaseResponse() { }
	public BaseResponse(bool _success)
	{
		Success = _success;
	}
}
