namespace Community.Owin.Security
{
    using System.Collections.Generic;
    using System.Security.Claims;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class OAuth2AuthenticatedContext : BaseContext
    {
        public OAuth2AuthenticatedContext(
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