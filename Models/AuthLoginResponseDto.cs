namespace jwtAuth.Models
{
    public class AuthLoginResponseDto
    {
        public required UserDto User { get; set; }
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
    }
}
