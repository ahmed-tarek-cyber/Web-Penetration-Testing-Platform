using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using WebScanner.Data;
using WebScanner.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace WebScanner.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext db, IConfiguration configuration)
        {
            _db = db;
            _configuration = configuration;
        }

        // =========================
        // 1. تسجيل جديد (Register)
        // =========================
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            string safeEmail = (request.Email ?? "").ToLower().Trim();
            string safeUsername = (request.Username ?? "").ToLower().Trim();
            string inviteCode = request.InviteCode ?? "";

            string correctCode = _configuration["AppSettings:InvitationCode"] ?? "SCANLY-57";

            if (inviteCode != correctCode)
            {
                return BadRequest(new { Message = "❌ Invalid Invitation Code." });
            }

            if (string.IsNullOrEmpty(safeEmail) || string.IsNullOrEmpty(safeUsername) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { Message = "All fields are required." });
            }

            if (_db.Users.Any(u => (u.Email ?? "").ToLower() == safeEmail))
            {
                return BadRequest(new { Message = "Email already exists" });
            }

            if (_db.Users.Any(u => (u.Username ?? "").ToLower() == safeUsername))
            {
                return BadRequest(new { Message = "Username already taken" });
            }

            var newUser = new User
            {
                Username = request.Username,
                Email = request.Email,
                Password = request.Password,
                CreatedAt = DateTime.UtcNow
            };

            _db.Users.Add(newUser);
            await _db.SaveChangesAsync();

            return Ok(new { Message = "✅ Registration Successful!" });
        }

        // =========================
        // 2. تسجيل الدخول (Login)
        // =========================
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            var user = _db.Users.FirstOrDefault(u =>
                (u.Email ?? "").ToLower() == (request.Email ?? "").ToLower() &&
                u.Password == request.Password);

            if (user == null)
            {
                return Unauthorized(new { Message = "❌ Invalid Email or Password" });
            }

            string token = CreateToken(user);

            return Ok(new
            {
                Message = "✅ Login Successful",
                Token = token,
                Username = user.Username
            });
        }

        // =========================
        // دالة إنشاء التوكن (تم التعديل لتوحيد المفتاح) 
        // =========================
        private string CreateToken(User user)
        {
            
            var keyString = "ThisIsAFallbackKeyForDevelopmentOnly12345";
            var key = Encoding.ASCII.GetBytes(keyString);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username ?? ""),
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email ?? "")
                }),
                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),

                 Issuer = "http://localhost:5000",
                Audience = "http://localhost:5000"
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}