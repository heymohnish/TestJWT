﻿namespace TestJWT.Models
{
    public class User
    {
        public int Id { get; set; }
        public string EmailId { get; set; } = "";
        public string Password { get; set; } = "";
        public string Phone { get; set; } = "";
        public string Role { get; set; } = "";
    }
}
