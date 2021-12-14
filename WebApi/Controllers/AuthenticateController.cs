using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace WebApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticateController : ControllerBase
{
    private readonly IIdentityService _identityService;

    public AuthenticateController(IIdentityService identityService)
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
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var authResponse = new AuthResponse();
            if (!ModelState.IsValid)
            {
                authResponse.Errors.AddRange(ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage)));
                return BadRequest(authResponse);
            }

            authResponse = await _identityService.RegisterAsync(request.Username, request.Email, request.Password);
            if (!authResponse.Success)
            {
                return BadRequest(authResponse);
            }

            // Imposta un Cookie HTTP Only con il refresh token, in modo che non sia memorizzato solo lato server
            // e mai visibile al client
            SetRefreshTokenCookie(authResponse.RefreshToken);

            authResponse.RefreshToken = null;
            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return BadRequest(e);
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
                authResponse.Errors.AddRange(ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage)));
                return BadRequest(authResponse);
            }

            Thread.Sleep(1000);
            if (!cancellationToken.IsCancellationRequested)
            {
                authResponse = await _identityService.LoginAsync(request.Email, request.Password);
                if (!authResponse.Success)
                {
                    return BadRequest(authResponse);
                }

                // Imposta un Cookie HTTP Only con il refresh token, in modo che non sia memorizzato solo lato server
                // e mai visibile al client
                SetRefreshTokenCookie(authResponse.RefreshToken);
            }

            authResponse.RefreshToken = null;
            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return BadRequest(e);
        }
    }

    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> Refresh([FromBody] string token)
    {
        try
        {
            var refreshToken = GetRefreshTokenCookie();
            var authResponse = await _identityService.RefreshTokenAsync(token, refreshToken);

            if (!authResponse.Success)
            {
                return BadRequest(authResponse);
            }

            // Imposta un Cookie HTTP Only con il refresh token, in modo che non sia memorizzato solo lato server
            // e mai visibile al client
            SetRefreshTokenCookie(authResponse.RefreshToken);

            authResponse.RefreshToken = null;
            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return BadRequest(e);
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
                authResponse.Errors.Add("RefreshToken is required");
                return BadRequest(authResponse);
            }

            authResponse = await _identityService.RevokeRefreshToken(refreshToken);
            if (!authResponse.Success)
            {
                return BadRequest(authResponse);
            }

            authResponse.RefreshToken = null;
            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return BadRequest(e);
        }
    }


    private void SetRefreshTokenCookie(string token)
    {
        Cookie refreshTokenCookie = new("refreshToken", new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7),
            IsEssential = true,
            Secure = false,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Domain = "localhost"
        });
        refreshTokenCookie.SetCookieValue(token, Response);
    }
    private string GetRefreshTokenCookie()
    {
        Cookie refreshTokenCookie = new("refreshToken");
        return refreshTokenCookie.GetCookieValue(Request);
    }
    private void DeleteRefreshTokenCookie()
    {
        Response.Cookies.Delete("refreshToken");
    }
    private string GetIpAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}
