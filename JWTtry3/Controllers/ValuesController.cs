using JWTtry3.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTtry3.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        public static Users user = new Users();
        public static UserDto users = new UserDto();
        private readonly IConfiguration _configuration;

        [HttpPost("register")]
        public async Task<ActionResult<Users>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(request);
            return Ok(token);
        }
        
        private string CreateToken(UserDto user)
        {

            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, (user.Password)),
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretKey!753159"));

            //var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
            //_configuration.GetSection("Jwt: Key").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

            //var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretKey!753159"));
            //var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            //var tokenOptions = new JwtSecurityToken(
            //    issuer: "http://localhost:5000",
            //    audience: "http://localhost:5000",
            //    expires: DateTime.Now.AddMinutes(3),
            //    claims:  new List<Claim>(),

            //    signingCredentials: signinCredentials
            //);

            //var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
            //return  tokenString ;

        }
    }
}
