namespace Community.Owin.Security
{
    public class GitHubAuthenticationOptions : OAuth2AuthenticationOptions
    {
        public GitHubAuthenticationOptions(
            string clientId,
            string clientSecret)
            : base("github", "GitHub", clientId, clientSecret)
        {
        }
    }
}