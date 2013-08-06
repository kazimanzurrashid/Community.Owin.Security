namespace Community.Owin.Security.GitHub
{
    using System;
    using System.Threading.Tasks;

    public class GitHubAuthenticationProvider : IGitHubAuthenticationProvider
    {
        public GitHubAuthenticationProvider()
        {
            #pragma warning disable 1998
            OnAuthenticated = async context => { };
            OnReturnEndpoint = async context => { };
            #pragma warning restore 1998
        }

        public Func<GitHubAuthenticatedContext, Task> OnAuthenticated
        {
            get; set;
        }

        public Func<GitHubReturnEndpointContext, Task> OnReturnEndpoint
        {
            get; set;
        }

        public virtual Task Authenticated(GitHubAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(GitHubReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}