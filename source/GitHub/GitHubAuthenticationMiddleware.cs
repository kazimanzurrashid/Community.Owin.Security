namespace Community.Owin.Security.GitHub
{
    using System;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using global::Owin;

    public class GitHubAuthenticationMiddleware :
        AuthenticationMiddleware<GitHubAuthenticationOptions>
    {
        private static readonly string MiddlewareFullName =
            typeof(GitHubAuthenticationMiddleware).FullName;
 
        private readonly ILogger logger;

        public GitHubAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            GitHubAuthenticationOptions options) : base(next, options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            logger = app.CreateLogger<GitHubAuthenticationMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new GitHubAuthenticationProvider();
            }

            if (Options.StateDataHandler != null)
            {
                return;
            }

            var fullName = new[] { MiddlewareFullName, Options.AuthenticationType };
            var dataProtector = app.CreateDataProtecter(fullName);
            Options.StateDataHandler = new ExtraDataHandler(dataProtector);
        }

        protected override AuthenticationHandler<GitHubAuthenticationOptions> CreateHandler()
        {
            return new GitHubAuthenticationHandler(logger);
        }
    }
}