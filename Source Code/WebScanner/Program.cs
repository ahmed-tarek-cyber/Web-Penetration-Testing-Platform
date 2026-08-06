using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebScanner.Services;
using WebScanner.Data;
using WebScanner.SignalR;
using WebScanner.Interfaces;
using WebScanner.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

// إعداد Kestrel
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(5000);
});

// -------------------- Services --------------------

builder.Services.AddControllers()
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
        opts.JsonSerializerOptions.PropertyNamingPolicy = null;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials());
});

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer("Server=localhost,1433;Database=ScanlyDB;User Id=sa;Password=YourStrongPass123;TrustServerCertificate=True;Encrypt=False;"));
var keyString = "ThisIsAFallbackKeyForDevelopmentOnly12345";
var key = Encoding.ASCII.GetBytes(keyString);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),

        ValidateIssuer = false,
        ValidateAudience = false,

        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero 
    };

   
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"🛑 Authentication Failed: {context.Exception.Message}");
            Console.ResetColor();
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✅ Token Validated Successfully for user: {context.Principal.Identity.Name}");
            Console.ResetColor();
            return Task.CompletedTask;
        },
        OnMessageReceived = context =>
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (!string.IsNullOrEmpty(token))
            {
                // طباعة أول 10 حروف من التوكن للتأكد أنه وصل
                Console.WriteLine($"📨 Token Received: {token.Substring(0, Math.Min(token.Length, 10))}...");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("⚠️ No Token received in Header!");
                Console.ResetColor();
            }
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddHttpClient();
builder.Services.AddHttpClient<AiScannerService>();
builder.Services.AddScoped<IScannerService, ScannerService>();
builder.Services.AddScoped<AiScannerService>();
// Chat bot services
builder.Services.AddSignalR();
builder.Services.AddScoped<ChatService>();
builder.Services.AddScoped<IChatAiService, GeminiService>();

var app = builder.Build();

// -------------------- Middleware --------------------

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowFrontend");

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHub<ChatHub>("/chatHub");

app.MapGet("/", () => Results.Redirect("/swagger/index.html"));

app.Run();