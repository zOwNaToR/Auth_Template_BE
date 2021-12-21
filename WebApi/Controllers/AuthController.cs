using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

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

            if (!cancellationToken.IsCancellationRequested)
            {
                authResponse = await _identityService.LoginAsync(request.Email, request.Password);
                if (!authResponse.Success)
                {
                    return BadRequest(authResponse);
                }
            }

            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return BadRequest(e);
        }
    }

    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> Refresh([FromBody] (string token, string refreshToken) tokens)
    {
        try
        {
            //var refreshToken = GetRefreshTokenCookie();
            var authResponse = await _identityService.RefreshTokenAsync(tokens.token, tokens.refreshToken);

            if (!authResponse.Success)
            {
                return BadRequest(authResponse);
            }

            return Ok(authResponse);
        }
        catch (Exception e)
        {
            return BadRequest(e);
        }
    }

    [HttpPost]
    [Route("revoke-token")]
    public async Task<IActionResult> RevokeToken([FromBody] string refreshToken)
    {
        try
        {
            //var refreshToken = GetRefreshTokenCookie();
            var authResponse = new AuthResponse();

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

    private string? GetRefreshTokenCookie()
    {
        if (Request.Headers.TryGetValue("rToken", out var values))
        {
            return values.ToString();
        }

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
