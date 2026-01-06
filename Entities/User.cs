namespace jwtAuth.Entities
{
    public class User
    {
        public string Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;

    }
}
