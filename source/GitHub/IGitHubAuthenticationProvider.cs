namespace Community.Owin.Security.GitHub
{
    using System.Threading.Tasks;

    public interface IGitHubAuthenticationProvider
    {
        Task Authenticated(GitHubAuthenticatedContext context);

        Task ReturnEndpoint(GitHubReturnEndpointContext context);
    }
}