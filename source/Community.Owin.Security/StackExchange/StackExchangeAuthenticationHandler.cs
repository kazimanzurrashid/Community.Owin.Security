namespace Community.Owin.Security
{
    using Newtonsoft.Json.Linq;

    public class StackExchangeAuthenticationHandler :
        OAuth2AuthenticationHandler<StackExchangeAuthenticationOptions>
    {
        public StackExchangeAuthenticationHandler() : base(
            "https://stackexchange.com/oauth",
            "https://stackexchange.com/oauth/access_token")
        {
        }

        protected override string UserInfoEndpoint
        {
            get
            {
                return "https://api.stackexchange.com/2.1/me" +
                    "?order=desc&sort=reputation&filter=default" +
                    "&key=" + Options.Key +
                    "&site=" + Options.Site;
            }
        }

        protected override OAuth2UserInfo ParseUserInfo(
            string content)
        {
            var json = JObject.Parse(content);

            var user = json["items"][0];
            var id = (string)user["user_id"];
            var name = (string)user["display_name"];

            return new OAuth2UserInfo
            {
                UserId = id,
                UserName = name
            };
        }
    }
}