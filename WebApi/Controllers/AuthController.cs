using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Net;

namespace WebApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IIdentityService _identityService;

    public AuthController(IIdentityService identityService)
    {
        _identityService = identityService;
    }

    [Authorize]
    [HttpGet]
    [Route("test")]
    public IActionResult Test()
    {
        return Ok("Hello");
    }


    [HttpPost]
    [Route("signup")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var response = new BaseResponse();
            if (!ModelState.IsValid)
            {
                response.Errors.AddRange(ModelState.GetErrors());
                return BadRequest(response);
            }

            response = await _identityService.RegisterAsync(request);
            if (!response.Success)
            {
                return BadRequest(response);
            }

            return Ok(response);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var authResponse = new AuthResponse();
            if (!ModelState.IsValid)
            {
                authResponse.Errors.AddRange(ModelState.GetErrors());
                return BadRequest(authResponse);
            }

            if (!cancellationToken.IsCancellationRequested)
            {
                authResponse = await _identityService.LoginAsync(request.Email, request.Password);
                if (!authResponse.Success)
                {
                    return Unauthorized(authResponse);
                }
            }

            SetRefreshTokenCookie(authResponse.RefreshToken);
            authResponse.HideRefreshToken();
            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var authResponse = new AuthResponse();
            
            var refreshToken = GetRefreshTokenCookie();
            if (string.IsNullOrEmpty(refreshToken))
            {
                authResponse.Errors.Add("Refresh token not found");
                return BadRequest(authResponse);
            }

            authResponse = await _identityService.RefreshTokenAsync(request.Token, refreshToken);
            if (!authResponse.Success)
            {
                return BadRequest(authResponse);
            }

            SetRefreshTokenCookie(authResponse.RefreshToken);
            authResponse.HideRefreshToken();
            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    [HttpPost]
    [Route("revoke-token")]
    public async Task<IActionResult> RevokeToken()
    {
        try
        {
            var authResponse = new AuthResponse();

            var refreshToken = GetRefreshTokenCookie();
            if (string.IsNullOrEmpty(refreshToken))
            {
                authResponse.Errors.Add("RefreshToken not found");
                return BadRequest(authResponse);
            }

            authResponse = await _identityService.RevokeRefreshTokenAsync(refreshToken);
            if (!authResponse.Success)
            {
                return BadRequest(authResponse);
            }

            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    [HttpPost]
    [Route("send-password-reset-link")]
    public async Task<IActionResult> SendPasswordResetLink([FromBody] SendPasswordResetLinkRequest request)
    {
        try
        {
            var resp = new SendLinkResetPasswordResponse();

            if (!ModelState.IsValid)
            {
                resp.Errors.AddRange(ModelState.GetErrors());
                return BadRequest(resp);
            }

            resp = await _identityService.SendPasswordResetLinkAsync(request.Email);

            resp.ResetLink = "";
            resp.ResetPasswordToken = "";
            return Ok(resp);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    [HttpPost]
    [Route("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            var resp = new BaseResponse();

            if (!ModelState.IsValid)
            {
                resp.Errors.AddRange(ModelState.GetErrors());
                return BadRequest(resp);
            }

            resp = await _identityService.ResetPasswordAsync(request.UserId, request.Password, request.Token);
            return Ok(resp);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    [HttpPost]
    [Route("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
    {
        try
        {
            var resp = new BaseResponse();

            if (!ModelState.IsValid)
            {
                resp.Errors.AddRange(ModelState.GetErrors());
                return BadRequest(resp);
            }

            resp = await _identityService.ConfirmEmailAsync(request.UserId, request.Token);
            return Ok(resp);
        }
        catch (Exception e)
        {
            return Problem(detail: e.Message, statusCode: (int)HttpStatusCode.InternalServerError);
        }
    }

    private string? GetRefreshTokenCookie()
    {
        if (Request.Cookies.TryGetValue("rToken", out string? value))
        {
            return value?.ToString();
        }

        return null;
    }
    private string? SetRefreshTokenCookie(string refreshToken)
    {
        var rtCoookie = new Dto.Cookie("rToken", new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7),
            IsEssential = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            //Path = "/",
            //Domain = "localhost"
        });

        rtCoookie.SetCookieValue(refreshToken, Response);

        return null;
    }
    private string GetIpAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}
