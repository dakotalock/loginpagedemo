using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// PostgreSQL Connection
var connectionString = "Host=localhost;Database=authdb;Username=postgres;Password=postgres123";
builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseNpgsql(connectionString));

// Identity Configuration
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthorization();

// JWT Configuration with fixed secret key
var secretKey = "SuperSecretKey123SuperSecretKey123SuperSecretKey123SuperSecretKey123SuperSecretKey123SuperSecretKey123";
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Auth endpoints
app.MapPost("/register", async (UserManager<IdentityUser> userManager, RegisterDto model) => {
    var user = new IdentityUser { UserName = model.Email, Email = model.Email };
    var result = await userManager.CreateAsync(user, model.Password);
    return result.Succeeded ? Results.Ok("User registered") : Results.BadRequest(result.Errors);
});

app.MapPost("/login", async (UserManager<IdentityUser> userManager, LoginDto model) => {
    var user = await userManager.FindByEmailAsync(model.Email);
    if (user == null) return Results.Unauthorized();

    var isValid = await userManager.CheckPasswordAsync(user, model.Password);
    if (!isValid) return Results.Unauthorized();

    var token = new JwtSecurityToken(
        claims: new[] { 
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email)
        },
        expires: DateTime.Now.AddDays(1),
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            SecurityAlgorithms.HmacSha256
        )
    );

    return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
});

app.MapGet("/protected", [Authorize] () => Results.Ok("Protected endpoint works!"));
app.MapGet("/public", () => Results.Ok("Public endpoint works!"));

app.Run();

public class ApplicationDbContext : IdentityDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
}

public class RegisterDto
{
    public string Email { get; set; }
    public string Password { get; set; }
}

public class LoginDto
{
    public string Email { get; set; }
    public string Password { get; set; }
}




