
using jwtAuth.Data;
using jwtAuth.Entities;
using jwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace jwtAuth.Services
{
    public class AuthService(AppDbContext context, IConfiguration configuration) : IAuthService
    {

        // Serveice for registering a new user ===========================================================>
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



        // Service for logging in a user ============================================================>
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
            var token = createAccessToken(user);

            // return response dto
            return new AuthLoginResponseDto
            {
                AccessToken = token,
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user), // every time a user is login the refresh token is also generated
                User = new UserDto
                {
                    Username = user.Username,
                    Role = user.Role,
                }
            };

        }



        // Refresh token service ============================================================>
        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            // validate the refresh token
            var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
            if (user is null)
            {
                return null;
            }
            // generate new refresh token and save to database
            var newRefreshToken = await GenerateAndSaveRefreshTokenAsync(user);
            // return new refresh token
            return new TokenResponseDto
            {
                AccessToken = createAccessToken(user),
                RefreshToken = newRefreshToken,
            };
        }


        // Validate Refresh token ============================================================>
        private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
        {
            var user = await context.Users.FindAsync(userId);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }
            return user;
        }



        // Generate refresh token =============================================================>
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
            
        }

        // Store refresh token in database ============================================================>
        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await context.SaveChangesAsync();

            return refreshToken;
        }




        // Create token method ============================================================>
        private string createAccessToken(User user)
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
            return configuration.GetValue<string>(appSettingsString)!;
        }
    }
}
