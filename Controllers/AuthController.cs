using jwtAuth.Entities;
using jwtAuth.Models;
using jwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


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


        // Refresh Token =======================================================================>
        [HttpPost("refresh-token")]
        public async Task<ActionResult<RefreshTokenRequestDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var serviceResponse = await authService.RefreshTokenAsync(request);
            if (serviceResponse == null || serviceResponse.AccessToken is null || serviceResponse.RefreshToken is null)
            {
                return Unauthorized("Invalid refresh token.");
            }
            return Ok(serviceResponse);
        }



        // ENDPOINT WITH ONLY JWT =======================================================================>
        [Authorize]
        [HttpGet("test")]
        public ActionResult<string> Test()
        {
            return Ok("The API is working!");
        }


        // ENDPOINT WITH JWT AND ROLE=======================================================================>
        [Authorize(Roles = "admin")]
        [HttpGet("admin")]
        public ActionResult AdminOnlyEndpoint()
        {
            return Ok("You are an admin!");
        }
    }
}
