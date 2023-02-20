using OAuthPoc.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace OAuthPoc.Controllers
{
    public class UserController : ApiController
    {
        IUserService _userService;
        public UserController()
            => _userService = new UserService();

        public UserController(IUserService userService)
            => _userService = userService;

        [HttpGet, Authorize(Roles = "Admin, User"), Route("api/user/GetAll")]
        public async Task<IHttpActionResult> GetAll()
            => Ok(await Task.Run(() => _userService.GetUserList()));

        [HttpGet, Authorize(Roles = "Admin"), Route("api/user/GetById")]
        public async Task<IHttpActionResult> GetById(int id)
            => Ok(await Task.Run(() => _userService.GetUserById(id)));

        [HttpGet, Authorize(Roles = "Admin"), Route("api/user/search")]
        public async Task<IHttpActionResult> Search(string name)
            => Ok(await Task.Run(() => _userService.SearchByName(name)));
    }
}