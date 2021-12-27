﻿using Microsoft.AspNetCore.Mvc;
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

            response = await _identityService.RegisterAsync(request.Username, request.Email, request.Password);
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
    // RefreshTokenRequest request
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
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
            //var refreshToken = GetRefreshTokenCookie();
            var authResponse = new AuthResponse();

            var refreshToken = GetRefreshTokenCookie();
            if (string.IsNullOrEmpty(refreshToken))
            {
                authResponse.Errors.Add("RefreshToken not found");
                return BadRequest(authResponse);
            }

            authResponse = await _identityService.RevokeRefreshToken(refreshToken);
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
