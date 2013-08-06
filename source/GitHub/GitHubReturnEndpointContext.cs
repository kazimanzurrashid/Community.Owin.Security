namespace Community.Owin.Security.GitHub
{
    using System.Collections.Generic;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class GitHubReturnEndpointContext : ReturnEndpointContext
    {
        public GitHubReturnEndpointContext(
            IDictionary<string, object> environment,
            AuthenticationTicket ticket,
            IDictionary<string, string> errorDetails) : 
            base(environment, ticket, errorDetails)
        {
        }
    }
}