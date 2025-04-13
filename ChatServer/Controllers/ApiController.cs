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
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;

namespace ChatServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
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
            User user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

            if (user == null)
                return Unauthorized("Invalid credentials");

            if (!await VerifyPasswordHashAsync(request.Password, user.PasswordHash, user.PasswordSalt))
                return Unauthorized("Invalid credentials");

            user.LastLogin = DateTime.UtcNow;
            var token = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(1);
            await _context.SaveChangesAsync();

            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(1),
                Path = "/api/refresh"
            });

            return Ok(new AuthResponse(
                Token: token,
                RefreshToken: refreshToken,
                PublicKey: Convert.ToBase64String(user.PublicKey)
            ));
        }

        // private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        // {
        //     using var hmac = new HMACSHA512(storedSalt);
        //     var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        //     return computedHash.SequenceEqual(storedHash);
        // }
        
        private async Task<bool> VerifyPasswordHashAsync(string password, byte[] storedHash, byte[] storedSalt)
        {
            var argon2Settings = _config.GetSection("Argon2");
            int degreeOfParallelism = argon2Settings.GetValue<int>("DegreeOfParallelism");
            int memorySize = argon2Settings.GetValue<int>("MemorySize");
            int iterations = argon2Settings.GetValue<int>("Iterations");
            int hashLength = argon2Settings.GetValue<int>("HashLength");

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Salt = storedSalt;
            argon2.DegreeOfParallelism = degreeOfParallelism;
            argon2.MemorySize = memorySize;
            argon2.Iterations = iterations;

            byte[] computedHash = await argon2.GetBytesAsync(hashLength);
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
                // Argon2 configuration
                var argon2Settings = _config.GetSection("Argon2");
                int degreeOfParallelism = argon2Settings.GetValue<int>("DegreeOfParallelism");
                int memorySize = argon2Settings.GetValue<int>("MemorySize");
                int iterations = argon2Settings.GetValue<int>("Iterations");
                int hashLength = argon2Settings.GetValue<int>("HashLength");
                
                if (await _context.Users.AnyAsync(u => u.Username == request.Username))
                    return Conflict("Username already exists");

                if (!IsPasswordStrong(request.Password))
                    return BadRequest("Password does not meet complexity requirements");
                
                // Generate salt
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Hash password with Argon2id
                var argon2 = new Argon2id(Encoding.UTF8.GetBytes(request.Password));
                argon2.Salt = salt;
                argon2.DegreeOfParallelism = degreeOfParallelism;
                argon2.MemorySize = memorySize;
                argon2.Iterations = iterations;

                byte[] hash = await argon2.GetBytesAsync(hashLength);

                byte[] publicKeyBytes;
                var publicKey = request.PublicKey.Trim();

                // Convert URL-safe Base64 to standard
                publicKey = publicKey.Replace('-', '+').Replace('_', '/');

                // Handle padding
                switch (publicKey.Length % 4)
                {
                    case 2: publicKey += "=="; break;
                    case 3: publicKey += "="; break;
                }

                // Validate Public Key
                try
                {
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                    
                    var ecParams = ecdsa.ExportParameters(false);
                    publicKeyBytes = new byte[65];
                    publicKeyBytes[0] = 0x04;
                    Buffer.BlockCopy(ecParams.Q.X, 0, publicKeyBytes, 1, 32);
                    Buffer.BlockCopy(ecParams.Q.Y, 0, publicKeyBytes, 33, 32);
                }
                catch (Exception)
                {
                    return BadRequest("Invalid public key format");
                }
                
                // Create User
                User user = new User
                {
                    Username = request.Username,
                    PasswordHash = hash,
                    PasswordSalt = salt,
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

                Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddDays(1),
                    Path = "/api/refresh"
                });

                return Ok(new AuthResponse(
                    Token: token,
                    RefreshToken: refreshToken,
                    PublicKey: Convert.ToBase64String(publicKeyBytes)
                ));
            }
            catch (Exception ex)
            {
                Console.Write(ex.InnerException);
                return StatusCode(500, "Registration error");
            }
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

            if (user == null || user.RefreshTokenExpiry <= DateTime.UtcNow)
                return Unauthorized("Invalid refresh token");

            var newJwt = GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();

            // Update cookie
            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7),
                Path = "/api/refresh"
            });

            return Ok(new { token = newJwt });
        }
        
        [HttpGet("users")]
        [Authorize]
        public async Task<IActionResult> GetUsers()
        {
            var authHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();

            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized("Missing or invalid Authorization header");
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            string userIdClaim = jwtToken.Claims.First().Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out Guid currentUserId))
            {
                return Unauthorized("Invalid token");
            }

            var users = await _context.Users
                .Select(u => new { u.PrimaryKey, u.Username, u.PublicKey })
                .ToListAsync();

            return Ok(users);
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