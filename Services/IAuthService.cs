using jwtAuth.Entities;
using jwtAuth.Models;

namespace jwtAuth.Services
{
    public interface IAuthService
    {
       Task<User?> RegisterAsync(UserDto request);

       Task<AuthLoginResponseDto?> LoginAsync(UserDto request);

       Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);
    }
}
