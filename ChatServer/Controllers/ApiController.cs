using ChatServer.Infrastructure;
using ChatServer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace ChatServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ApiController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;

        public ApiController(AppDbContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == request.Username);

            if (user == null)
                return Unauthorized("Invalid credentials");

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
                return Unauthorized("Invalid credentials");

            user.LastLogin = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            var token = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();

            return Ok(new AuthResponse(
                Token: token,
                RefreshToken: refreshToken,
                PublicKey: Convert.ToBase64String(user.PublicKey)
            ));
        }

        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            using var hmac = new HMACSHA512(storedSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(storedHash);
        }

        private string GenerateJwtToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));

            var credentials = new SigningCredentials(
                securityKey, SecurityAlgorithms.HmacSha512Signature);

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.PrimaryKey.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim("public_key", Convert.ToBase64String(user.PublicKey))
        };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                // Validate request
                if (await _context.Users.AnyAsync(u => u.Username == request.Username))
                    return Conflict("Username already exists");

                if (!IsPasswordStrong(request.Password))
                    return BadRequest("Password does not meet complexity requirements");

                // Convert Base64 string to byte array
                byte[] publicKeyBytes;
                var publicKey = request.PublicKey.Trim();

                // Check for URL-safe Base64 and convert to standard
                publicKey = publicKey.Replace('-', '+').Replace('_', '/');

                // Handle padding
                switch (publicKey.Length % 4)
                {
                    case 2: publicKey += "=="; break;
                    case 3: publicKey += "="; break;
                }

                try
                {
                    publicKeyBytes = Convert.FromBase64String(publicKey);
                }
                catch (FormatException)
                {
                    return BadRequest("Invalid Base64 public key format");
                }

                // Validate public key length (32 bytes for X25519)
                if (publicKeyBytes.Length != 32)
                    return BadRequest("Invalid public key length. Expected 32 bytes");

                // Create password hash
                using var hmac = new HMACSHA512();
                var passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(request.Password));
                var passwordSalt = hmac.Key;

                // Create user
                var user = new User
                {
                    Username = request.Username,
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt,
                    PublicKey = publicKeyBytes
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Generate tokens
                var token = GenerateJwtToken(user);
                var refreshToken = GenerateRefreshToken();

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
                await _context.SaveChangesAsync();

                return Ok(new AuthResponse(
                    Token: token,
                    RefreshToken: refreshToken,
                    PublicKey: Convert.ToBase64String(user.PublicKey)
                ));
            }
            catch (Exception ex)
            {
                // Log the exception
                return StatusCode(500, "An error occurred during registration");
            }
        }

        private bool IsPasswordStrong(string password)
        {
            // OWASP password complexity recommendations
            const int minLength = 12;
            var hasUpper = new Regex(@"[A-Z]");
            var hasLower = new Regex(@"[a-z]");
            var hasDigit = new Regex(@"[0-9]");
            var hasSpecial = new Regex(@"[!@#$%^&*()_+=\[{\]};:<>|./?,-]");

            return password.Length >= minLength &&
                   hasUpper.IsMatch(password) &&
                   hasLower.IsMatch(password) &&
                   hasDigit.IsMatch(password) &&
                   hasSpecial.IsMatch(password);
        }

        
    }
}




// DTOs
public record LoginRequest(string Username, string Password);
public record AuthResponse(string Token, string RefreshToken,string PublicKey);
public record RegisterRequest(string Username,string Password,string PublicKey);