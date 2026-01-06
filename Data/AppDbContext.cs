

using jwtAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace jwtAuth.Data


{
    public class AppDbContext(DbContextOptions<AppDbContext> options): DbContext(options) {
        public DbSet<User> Users { get; set; }


    }
}
