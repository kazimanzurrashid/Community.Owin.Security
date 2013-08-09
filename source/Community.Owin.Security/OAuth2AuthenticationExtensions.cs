namespace Owin
{
    using System;

    using Community.Owin.Security;

    using Microsoft.Owin.Security;

    public static class OAuth2AuthenticationExtensions
    {
        public static IAppBuilder UseGitHubAuthentication(
            this IAppBuilder app, 
            string clientId,
            string clientSecret)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            var option = new GitHubAuthenticationOptions(
                clientId,
                clientSecret)
            {
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            };

            return UseGitHubAuthentication(app, option);
        }

        public static IAppBuilder UseGitHubAuthentication(
            this IAppBuilder app,
            GitHubAuthenticationOptions options)
        {
            return UseAuthentication(
                typeof(OAuth2AuthenticationMiddleware<GitHubAuthenticationHandler, GitHubAuthenticationOptions>),
                app,
                options);
        }

        public static IAppBuilder UseStackExchangeAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret,
            string key,
            string site)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            var option = new StackExchangeAuthenticationOptions(
                clientId,
                clientSecret,
                key,
                site)
            {
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            };

            return UseStackExchangeAuthentication(app, option);
        }

        public static IAppBuilder UseStackExchangeAuthentication(
            this IAppBuilder app,
            StackExchangeAuthenticationOptions options)
        {
            return UseAuthentication(
                typeof(OAuth2AuthenticationMiddleware<StackExchangeAuthenticationHandler, StackExchangeAuthenticationOptions>),
                app,
                options);
        }

        private static IAppBuilder UseAuthentication(
            Type type,
            IAppBuilder app,
            OAuth2AuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            var args = new object[] { app, options };
            app.Use(type, args);

            return app;
        }
    }
}