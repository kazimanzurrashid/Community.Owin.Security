namespace Community.Owin.Security.GitHub
{
    using System.Collections.Generic;
    using System.Security.Claims;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class GitHubAuthenticatedContext : BaseContext
    {
        public GitHubAuthenticatedContext(
            string accessToken,
            string userId,
            string userName,
            IDictionary<string, object> environment)
            : base(environment)
        {
            AccessToken = accessToken;
            UserId = userId;
            UserName = userName;
        }

        public string AccessToken
        {
            get;
            private set;
        }

        public string UserId { get; private set; }

        public string UserName { get; private set; }

        public AuthenticationExtra Extra { get; set; }

        public ClaimsIdentity Identity { get; set; }
    }
}