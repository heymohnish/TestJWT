using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestJWT.Models;

namespace TestJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        IConfiguration _configuration;
        public AuthController(IConfiguration config)
        {
            _configuration = config;
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(User user)
        {
            IActionResult response = Unauthorized();
            if (user != null)
            {
                if (user.EmailId.Equals("test@email.com") && user.Password.Equals("a"))
                {
                    var issuer = _configuration["Jwt:Issuer"];
                    var audience = _configuration["Jwt:Audience"];

                    var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
                    var signingCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha512Signature
                    );
                    var subject = new ClaimsIdentity(new[]
                    {  
                        new Claim (JwtRegisteredClaimNames.Sub, user.EmailId),
                        new Claim (JwtRegisteredClaimNames.Email, user.EmailId),
                        new Claim(ClaimTypes.Role, "user")
                        });
                    var expires = DateTime.UtcNow.AddMinutes(10);
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = subject,
                        Expires = DateTime.UtcNow.AddMinutes(10),
                        Issuer = issuer,
                        Audience = audience,
                        SigningCredentials = signingCredentials
                    };
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    var jwtToken = tokenHandler.WriteToken(token);
                    return Ok(jwtToken);
                }
            }
            return response;

        }
    }
}
