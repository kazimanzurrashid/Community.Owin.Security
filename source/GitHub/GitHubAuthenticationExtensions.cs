namespace Owin
{
    using System;

    using Microsoft.Owin.Security;

    using Community.Owin.Security.GitHub;

    public static class GitHubAuthenticationExtensions
    {
        private static readonly Type MiddlewareType = typeof(GitHubAuthenticationMiddleware);

        public static IAppBuilder UseGitHubAuthentication(
            this IAppBuilder app, 
            string clientId,
            string clientSecret)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            var option = new GitHubAuthenticationOptions(clientId, clientSecret)
            {
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            };

            return UseGitHubAuthentication(app, option);
        }

        public static IAppBuilder UseGitHubAuthentication(
            this IAppBuilder app,
            GitHubAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            var args = new object[] { app, options };
            app.Use(MiddlewareType, args);

            return app;
        }
    }
}