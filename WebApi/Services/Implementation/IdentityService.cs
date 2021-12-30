using Common;
using EmailSender;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;

namespace WebApi.Services;

public class IdentityService : IIdentityService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly IEmailSender _emailSender;
    private readonly IDataProtector _dataProtector;
    private readonly HttpContext _httpContext;
    private readonly TokenValidationParameters _tokenValidationParameters;
    private readonly AppDbContext _context;
    private readonly AppSettings _appSettings;

    public IdentityService(UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        TokenValidationParameters tokenValidationParameters,
        RoleManager<IdentityRole<Guid>> roleManager,
        IEmailSender emailSender,
        IDataProtectionProvider dataProtectionProvider,
        IHttpContextAccessor httpContextAccessor,
        IOptions<AppSettings> appSettings,
        AppDbContext context)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenValidationParameters = tokenValidationParameters;
        _roleManager = roleManager;
        _emailSender = emailSender;
        _dataProtector = dataProtectionProvider.CreateProtector("DataProtectorTokenProvider");
        _httpContext = httpContextAccessor.HttpContext;
        _appSettings = appSettings.Value;
        _context = context;
    }


    #region Public interface methods
    public async Task<BaseResponse> RegisterAsync(string username, string email, string password)
    {
        var response = new BaseResponse();
        var existingUser = await _userManager.FindByEmailAsync(email);

        if (existingUser != null)
        {
            response.Errors.Add("User with this email address already exists");
            return response;
        }

        var newUser = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            UserName = username
        };

        var createdUser = await _userManager.CreateAsync(newUser, password);
        if (!createdUser.Succeeded)
        {
            response.Errors.AddRange(createdUser.Errors.Select(x => x.Description));
            return response;
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
        var confirmEmailLink = $"{_httpContext.Request.GetClientBaseUrl()}/confirm-email?token={WebUtility.UrlEncode(token)}&userId={newUser.Id}";

        await _emailSender.SendAsync(null, newUser.Email, "Confirm Email .NET Auth", $"<a href=\"{confirmEmailLink}\">Click here to confirm your email</a>");

        response.Success = true;
        return response;
        //return await GenerateAuthenticationResultForUserAsync(newUser);
    }
    public async Task<AuthResponse> LoginAsync(string email, string password)
    {
        var errorResponse = new AuthResponse();
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            errorResponse.Errors.Add("Wrong email and password");
            return errorResponse;
        }

        var userHasValidPassword = await _userManager.CheckPasswordAsync(user, password);
        if (!userHasValidPassword)
        {
            errorResponse.Errors.Add("Wrong email and password");
            return errorResponse;
        }

        var result = await _signInManager.PasswordSignInAsync(user, password, true, false);
        if (!result.Succeeded)
        {
            errorResponse.Errors.Add("Wrong email and password");
            return errorResponse;
        }

        return await GenerateAuthenticationResultForUserAsync(user);
    }
    public async Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken)
    {
        var errorResponse = new AuthResponse();

        // Validate old token expiry date if present
        if (!string.IsNullOrEmpty(token))
        {
            var validatedToken = GetPrincipalFromToken(token);

            if (validatedToken == null)
            {
                errorResponse.Errors.Add("Invalid Token");
                return errorResponse;
            }

            var expiryDateUnix = long.Parse(validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            var expiryDateTimeUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(expiryDateUnix);

            if (expiryDateTimeUtc > DateTime.UtcNow)
            {
                errorResponse.Errors.Add("This token hasn't expired yet");
                return errorResponse;
            }

            //var jti = validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            //if (dbRefreshToken.JwtId != jti)
            //{
            //    errorResponse.Errors.Add("This refresh token does not match this JWT");
            //    return errorResponse;
            //}
        }

        // Check token validity
        var dbRefreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);
        if (dbRefreshToken == null)
        {
            errorResponse.Errors.Add("This refresh token does not exist");
            return errorResponse;
        }
        if (dbRefreshToken.Invalidated)
        {
            await InvalidateAllUserRefreshTokensAsync(dbRefreshToken.UserId);
            errorResponse.Errors.Add("This refresh token has been invalidated");
            return errorResponse;
        }
        if (DateTime.UtcNow > dbRefreshToken.ExpiryDate)
        {
            errorResponse.Errors.Add("This refresh token has expired");
            return errorResponse;
        }
        if (dbRefreshToken.Used)
        {
            errorResponse.Errors.Add("This refresh token has been used");
            return errorResponse;
        }

        dbRefreshToken.Used = true;
        _context.RefreshTokens.Update(dbRefreshToken);
        await _context.SaveChangesAsync();

        var user = await _userManager.FindByIdAsync(dbRefreshToken.UserId.ToString());
        return await GenerateAuthenticationResultForUserAsync(user);
    }
    public async Task<AuthResponse> RevokeRefreshTokenAsync(string refreshToken)
    {
        var errorResponse = new AuthResponse();

        var dbRefreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);
        if (dbRefreshToken == null)
        {
            errorResponse.Errors.Add("Token not found");
            return errorResponse;
        }
        if (dbRefreshToken.Invalidated)
        {
            errorResponse.Errors.Add("Token is not active");
            return errorResponse;
        }

        dbRefreshToken.Invalidated = true;
        await _context.SaveChangesAsync();

        return new AuthResponse
        {
            Success = true
        };
    }
    public async Task<SendLinkResetPasswordResponse> SendPasswordResetLinkAsync(string email)
    {
        var response = new SendLinkResetPasswordResponse();

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            response.Errors.Add("User with this email address does not exits");
            return response;
        }
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            response.Errors.Add("Email not confirmed yet");
            return response;
        }

        response.ResetPasswordToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        response.ResetLink = $"{_httpContext.Request.GetClientBaseUrl()}/reset-password" +
            $"?token={WebUtility.UrlEncode(response.ResetPasswordToken)}&userId={user.Id}";

        await _emailSender.SendAsync(null, user.Email, "Reset Email .NET Auth", $"<a href=\"{response.ResetLink}\">Click here to reset your password</a>");

        response.Success = true;
        return response;
    }
    public async Task<BaseResponse> ResetPasswordAsync(Guid userId, string password, string resetPasswordToken)
    {
        var response = new BaseResponse();

        try
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                response.Errors.Add("Invalid token");
                return response;
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordToken, password);
            if (!result.Succeeded)
            {
                response.Errors.AddRange(result.Errors.Select(x => x.Description));
                return response;
            }

            _ = Utility.IgnoreErrors(async () =>
            {
                await _emailSender.SendAsync(null, user.Email, "Reset Email .NET Auth", $"Your password has been resetted.");
            });

            response.Success = true;
        }
        catch (Exception e)
        {
            response.Errors.Add(e.Message);
        }


        return response;
    }
    public async Task<BaseResponse> ConfirmEmailAsync(Guid userId, string confirmEmailToken)
    {
        var response = new BaseResponse();
        
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            response.Errors.Add("Invalid token");
            return response;
        }

        var result = await _userManager.ConfirmEmailAsync(user, confirmEmailToken);
        if (!result.Succeeded)
        {
            response.Errors.AddRange(result.Errors.Select(x => x.Description));
            return response;
        }

        _ = Utility.IgnoreErrors(async () =>
        {
            await _emailSender.SendAsync(null, user.Email, "Email confirmed .NET Auth", $"Your email has been confirmed.");
        });

        response.Success = true;
        return response;
    }
    #endregion

    #region Generate Token/RefreshToken
    private SecurityToken GenerateJwtToken(JwtSecurityTokenHandler tokenHandler, IEnumerable<Claim> claims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.JWT.SecretKey));
        var UtcNow = DateTime.UtcNow;

        //Create token
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            //Expires = UtcNow.AddMinutes(_appSettings.JWT.TokenExpiresIn),
            Expires = UtcNow.AddSeconds(45),
            SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
            Audience = _appSettings.JWT.ValidAudience,
            Issuer = _appSettings.JWT.ValidIssuer
        };

        return tokenHandler.CreateToken(tokenDescriptor);
    }
    private async Task<RefreshToken> GenerateJwtRefreshTokenAsync(Guid UserId, string TokenId)
    {
        var refreshToken = new RefreshToken
        {
            JwtId = TokenId,
            UserId = UserId,
            CreationDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddDays(_appSettings.JWT.RefreshTokenExpiresIn)
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();

        return refreshToken;
    }
    #endregion

    #region Get Principal/Claims
    private async Task<IEnumerable<Claim>> GetTokenClaimsAsync(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("Id", user.Id.ToString())
        };

        var userClaims = await _userManager.GetClaimsAsync(user);
        claims.AddRange(userClaims);

        // Take user's roles e map them to Claims. For each role it takes all realted claims
        var userRoles = await _userManager.GetRolesAsync(user);
        foreach (var userRole in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, userRole));
            var role = await _roleManager.FindByNameAsync(userRole);
            if (role == null) continue;

            var roleClaims = await _roleManager.GetClaimsAsync(role);
            //claims.AddRange(roleClaims.Except(claims));
            foreach (var roleClaim in roleClaims)
            {
                if (claims.Contains(roleClaim))
                    continue;

                claims.Add(roleClaim);
            }
        }

        return claims;
    }
    private ClaimsPrincipal? GetPrincipalFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        try
        {
            var tokenValidationParameters = _tokenValidationParameters.Clone();
            tokenValidationParameters.ValidateLifetime = false;

            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
            if (!IsJwtAndValidAlgorithm(validatedToken))
            {
                return null;
            }

            return principal;
        }
        catch
        {
            return null;
        }
    }
    #endregion

    private async Task InvalidateAllUserRefreshTokensAsync(Guid userId)
    {
        var dbRefreshTokens = await _context.RefreshTokens.Where(x => x.UserId == userId).ToListAsync();
        dbRefreshTokens.ForEach(x => x.Invalidated = true);
        await _context.SaveChangesAsync();
    }
    private async Task<AuthResponse> GenerateAuthenticationResultForUserAsync(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var claims = await GetTokenClaimsAsync(user);
        var token = GenerateJwtToken(tokenHandler, claims);
        var refreshToken = await GenerateJwtRefreshTokenAsync(user.Id, token.Id);

        return new AuthResponse
        {
            Success = true,
            Token = tokenHandler.WriteToken(token),
            RefreshToken = refreshToken.Token,
            ExpireDate = token.ValidTo,
            UserName = user.UserName,
            Roles = claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToList()
        };
    }
    private static bool IsJwtAndValidAlgorithm(SecurityToken token)
    {
        return (token is JwtSecurityToken jwtToken) &&
            jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
    }

}
