

using jwtAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace jwtAuth.Data


{
    public class AppDbContext(DbContextOptions<AppDbContext> options): DbContext(options) {
        // Here we define the Users DbSet to represent the Users table in the database

        // User Entity table
        public DbSet<User> Users { get; set; }

        


    }
}
