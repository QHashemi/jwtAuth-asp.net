using jwtAuth.Dtos;
using jwtAuth.Entities;

namespace jwtAuth.Services
{
    public interface IAuthService
    {
       Task<User?> RegisterAsync(Entities.Models.UserDto request);
       Task<AuthLoginResponseDto?> LoginAsync(Entities.Models.UserDto request);
    }
}
