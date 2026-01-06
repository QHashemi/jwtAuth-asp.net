using jwtAuth.Entities;
using jwtAuth.Entities.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace jwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IConfiguration configuration) : ControllerBase
    {
        public static User user = new User();


        // Register user
        [HttpPost("register")]

        // <User> means the ActionResult will return a User object
        public ActionResult<User> Register(UserDto request)
        {
            // hash password
            var hashedPassowrd = new PasswordHasher<User>().HashPassword(user, request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashedPassowrd;

            return Ok(user);
        }



        // Login user
        [HttpPost("login")]
        public ActionResult<string> Login(UserDto request)
        {
            // if use not found
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            // verify password
            var result = new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed;
            if (result)
            {
                return BadRequest("Wrong password.");
            }

            // asing token and send response
            return Ok(
                new  {
                user = user,
                token = createToken(user)
            });
        }



        // Create token method
       private string createToken(User user)
        {
            // Create claims that will be stored inside the JWT (user identity data)
             var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            // Create a security key from the secret used to sign the token
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(getAppSettings("Token")!)
            );

            // Define the signing credentials using HMAC SHA-512
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            // Create the JWT with issuer, audience, claims, expiration, and signature
            var tokenDescriptor = new JwtSecurityToken(
                issuer: getAppSettings("Issuer"),
                audience: getAppSettings("Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: credentials
            );

            // Generate and return the encoded JWT string
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        // get app settings
        private string getAppSettings(string setting)
        {
            var appSettingsString = $"AppSettings:{setting}";
            return configuration.GetValue<string>(appSettingsString);
        }
    }
}
