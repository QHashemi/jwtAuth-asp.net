
using jwtAuth.Data;
using jwtAuth.Dtos;
using jwtAuth.Entities;
using jwtAuth.Entities.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jwtAuth.Services
{
    public class AuthService(AppDbContext context, IConfiguration configuration) : IAuthService
    {

        // Serveice for registering a new user
        public async Task<User?> RegisterAsync(UserDto request)
        {
            // Check if user already exists
            var isUserExits = await context.Users.AnyAsync(user => user.Username == request.Username);
            if (isUserExits)
            {
                return null;
            }

            // create new user if not exists
            var user = new User();

            // hash password
            var hashedPassowrd = new PasswordHasher<User>().HashPassword(user, request.Password);

            // set user data
            user.Username = request.Username;
            user.PasswordHash = hashedPassowrd;
            user.Role = request.Role;

            // save data to database
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();

            // return user
            return user;
        }




        public async Task<AuthLoginResponseDto> LoginAsync(UserDto request)
        {
            // find user by username
            var user = await context.Users.FirstOrDefaultAsync(user => user.Username == request.Username);
            if (user == null) 
            {
                return null;
            }

            // verify password
            var result = new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed;
            if (result)
            {
                return null;
            }

            // create and return token
            var token = createToken(user);

            // return response dto
            return new AuthLoginResponseDto
            {
                Token = token,
                User = new UserDto
                {
                    Username = user.Username,
                    Role = user.Role,
                }
            };

        }




        // Create token method
        private string createToken(User user)
        {
            // Create claims that will be stored inside the JWT (user identity data)
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
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
