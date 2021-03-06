using Common.Dto;
using EmailSender;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

const string MyCorsPolicy = ".NET6Auth_CorsPolicy";

void ConfigureServices(IServiceCollection services, IConfiguration configuration)
{
    services.AddControllers();
    services.AddCors(options =>
    {
        options.AddPolicy(name: MyCorsPolicy,
            builder =>
            {
                builder
                //.AllowAnyOrigin()
                .WithOrigins("http://localhost:3000")
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
            });
    });

    //services.Configure<CookiePolicyOptions>(options =>
    //{
    //    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
    //    options.CheckConsentNeeded = context => true;
    //    options.MinimumSameSitePolicy = SameSiteMode.None;
    //});

    services.AddDbContext<AppDbContext>(options => options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly("DAL")));

    services.AddIdentity<ApplicationUser, IdentityRole<Guid>>()
        .AddEntityFrameworkStores<AppDbContext>()
        .AddDefaultTokenProviders();

    services.Configure<IdentityOptions>(options =>
    {
        options.SignIn.RequireConfirmedEmail = false;
    });

    var tokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAudience = configuration["AppSettings:JWT:ValidAudience"],
        ValidIssuer = configuration["AppSettings:JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["AppSettings:JWT:SecretKey"])),
        // set ClockSkew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
        ClockSkew = TimeSpan.Zero
    };

    // Dependency Injection
    var appSettingsConfig = configuration.GetSection("AppSettings");
    appSettingsConfig["SMTP:Password"] += "7wpQfgtD";
    services.Configure<AppSettings>(appSettingsConfig);

    services.AddSingleton(tokenValidationParameters);
    services.AddScoped<IIdentityService, IdentityService>();
    services.AddScoped<IEmailSender, CustomEmailSender>();
    services.AddScoped<IUserService, UserService>();

    // Adding Authentication  
    services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = tokenValidationParameters;
    });

    services.AddSwaggerGen(swagger =>
    {
        //This is to generate the Default UI of Swagger Documentation    
        swagger.SwaggerDoc("v1", new OpenApiInfo
        {
            Version = "v1",
            Title = ".NET 6 WebApi Auth",
            Description = "Authentication and Authorization in ASP.NET Core 6 with JWT and Swagger",
        });
        // To Enable authorization using Swagger (JWT)    
        swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
        {
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Enter 'Bearer' [space] and then your valid token in the text input below.\r\n\r\nExample: \"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
        });
        swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                System.Array.Empty<string>()
            }
        });
    });
}

var builder = WebApplication.CreateBuilder(args);
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
ConfigureServices(builder.Services, builder.Configuration);

// Middleware
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors(MyCorsPolicy);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
