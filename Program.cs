
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "your-issuer",
            ValidAudience = "your-audience",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-secret-key"))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Use middleware
app.UseMiddleware<LoggingMiddleware>();
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseMiddleware<AuthenticationMiddleware>();
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new { error = "An unexpected error occurred", details = ex.Message });
    

    }
});

app.UseAuthentication();
app.UseAuthorization();

var users = new List<User>
{
    new User { Id = 1, Name = "John Doe", Email = "john.doe@example.com", Department = "HR" },
    new User { Id = 2, Name = "Jane Smith", Email = "jane.smith@example.com", Department = "IT" }
};

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/api/users", () => users);

app.MapGet("/api/users/{id}", (int id) =>
{
    var user = users.FirstOrDefault(u => u.Id == id);
    return user is not null ? Results.Ok(user) : Results.NotFound("User not found");
});

app.MapPost("/api/users", (User user) =>
{
    // Validate user data
    if (string.IsNullOrEmpty(user.Name) || string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Department))
    {
        return Results.BadRequest("Invalid user data");
    }

    user.Id = users.Max(u => u.Id) + 1;
    users.Add(user);
    return Results.Created($"/api/users/{user.Id}", user);
});
app.MapPut("/api/users/{id}", (int id, User updatedUser) =>
{
    var user = users.FirstOrDefault(u => u.Id == id);
    if (user is null) return Results.NotFound();

    user.Name = updatedUser.Name;
    user.Email = updatedUser.Email;
    user.Department = updatedUser.Department;
    return Results.NoContent();
});

app.MapDelete("/api/users/{id}", (int id) =>
{
    var user = users.FirstOrDefault(u => u.Id == id);
    if (user is null) return Results.NotFound();

    users.Remove(user);
    return Results.NoContent();
});

app.Run();

class User
{
    public int Id { get; set; }
   required public string Name { get; set; }
  required  public string Email { get; set; }
   required public string Department { get; set; }
}



public class LoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<LoggingMiddleware> _logger;

    public LoggingMiddleware(RequestDelegate next, ILogger<LoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Log the incoming request
        _logger.LogInformation($"Incoming request: {context.Request.Method} {context.Request.Path}");

        // Continue to the next middleware component
        await _next(context);

        // Log the outgoing response
        _logger.LogInformation($"Outgoing response: {context.Response.StatusCode}");
    }
}

public class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;

    public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred.");
            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json";
            var response = new { error = "Internal server error." };
            await context.Response.WriteAsJsonAsync(response);
        }
    }
}

public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuthenticationMiddleware> _logger;

    public AuthenticationMiddleware(RequestDelegate next, ILogger<AuthenticationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var token))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: No token provided" });
            return;
        }

        try
        {
            // Validate the token (you can implement your own token validation logic here)
            var isValidToken = ValidateToken(token.ToString());

            if (!isValidToken)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Invalid token" });
                return;
            }

            // Continue to the next middleware component
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while validating the token.");
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new { error = "Internal server error" });
        }
    }

    private bool ValidateToken(string token)
    {
        // Implement your token validation logic here
        // For example, validate the token against a secret key or use a library to decode and verify the token
        return token == "your-valid-token"; // Replace with your validation logic
    }
}