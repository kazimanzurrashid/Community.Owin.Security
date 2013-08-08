namespace Community.Owin.Security
{
    using Newtonsoft.Json.Linq;

    public class StackExchangeAuthenticationHandler :
        OAuth2AuthenticationHandler
    {
        public StackExchangeAuthenticationHandler() : base(
            "https://stackexchange.com/oauth",
            "https://stackexchange.com/oauth/access_token",
            "https://api.stackexchange.com/2.1/me")
        {
        }

        protected override OAuth2UserInfo ParseUserInfo(
            string content)
        {
            var json = JObject.Parse(content);

            return new OAuth2UserInfo
            {
                UserId = (string)json["user_id"],
                UserName = (string)json["display_name"]
            };
        }
    }
}