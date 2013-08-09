namespace Community.Owin.Security
{
    using Newtonsoft.Json.Linq;

    public class GitHubAuthenticationHandler :
        OAuth2AuthenticationHandler<GitHubAuthenticationOptions>
    {
        public GitHubAuthenticationHandler() : base(
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token")
        {
        }

        protected override string UserInfoEndpoint
        {
            get
            {
                return "https://api.github.com/user";
            }
        }

        protected override OAuth2UserInfo ParseUserInfo(
            string content)
        {
            var json = JObject.Parse(content);

            return new OAuth2UserInfo
            {
                UserId = (string)json["id"],
                UserName = (string)json["login"]
            };
        }
    }
}