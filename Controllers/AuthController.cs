using jwtAuth.Entities;
using jwtAuth.Entities.Models;
using jwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;


namespace jwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {


        // Register user ======================================================================>
        [HttpPost("register")]

        // <User> means the ActionResult will return a User object
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user == null)
            {
                return BadRequest("Username already exists!");
            }

            return Ok(user);

        }



        // Login user =======================================================================>
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var serivceResponse = await authService.LoginAsync(request);
            if (serivceResponse == null)
            {
                return BadRequest("Invalid username or password.");
            }
            return Ok(serivceResponse);

        }


        // TEST Sequre END POINT =======================================================================>
        [Authorize]
        [HttpGet("test")]
        public ActionResult<string> Test()
        {
            return Ok("The API is working!");
        }
    }
}
