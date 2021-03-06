using System.Collections.Generic;
using System.Threading.Tasks;
using DatingApp.API.Helpers;
using DatingApp.API.Models;

namespace DatingApp.API.Data
{
    public interface IDatingRepository
    {
         void Add<T>(T entity) where T: class;
         void Delete<T>(T entity) where T: class;
         Task<bool> SaveAll();
         Task<PagedList<User>> GetUsers(UserParams userParams);
         Task<User> GetUser(int id, bool isCurrentUser);
         Task<Photo> GetPhoto(int id);
         Task<Photo> GetMainPhotoForUser(int userId);    
         Task<Like> GetLike(int userId, int recipientId);
         Task<Messages> GetMessage(int id);
         Task<PagedList<Messages>> GetMessagesForUser(MessageParams messageParams);
         Task<IEnumerable<Messages>> GetMessageThread(int userId, int recipientId);
         
    }
}