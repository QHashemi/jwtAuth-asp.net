using jwtAuth.Entities.Models;

namespace jwtAuth.Dtos
{
    public class AuthLoginResponseDto
    {
        public UserDto User { get; set; }
        public string Token { get; set; }   
    }
}
