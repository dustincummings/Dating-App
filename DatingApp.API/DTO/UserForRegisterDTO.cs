using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.DTO
{
    public class UserForRegisterDTO
    {
        [Required]
        public string Username { get; set; } 
        [Required]
        [StringLength(8, MinimumLength=4, ErrorMessage = "Your password must be 4-8 characters")]   
        public string Password { get; set; }
    }
}