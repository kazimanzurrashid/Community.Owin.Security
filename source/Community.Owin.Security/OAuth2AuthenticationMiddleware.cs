namespace Community.Owin.Security
{
    using System;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using global::Owin;

    public class OAuth2AuthenticationMiddleware<THandler, TOptions> :
        AuthenticationMiddleware<TOptions>
        where THandler : OAuth2AuthenticationHandler<TOptions>, new()
        where TOptions : OAuth2AuthenticationOptions
    {
        private readonly ILogger logger;

        public OAuth2AuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            TOptions options)
            : base(next, options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            logger = app.CreateLogger<OAuth2AuthenticationMiddleware<THandler, TOptions>>();

            if (Options.Provider == null)
            {
                Options.Provider = new OAuth2AuthenticationProvider();
            }

            if (Options.StateDataHandler != null)
            {
                return;
            }

            var fullName = new[]
            {
                typeof(OAuth2AuthenticationMiddleware<THandler, TOptions>).FullName,
                Options.AuthenticationType
            };

            var dataProtector = app.CreateDataProtecter(fullName);
            Options.StateDataHandler = new ExtraDataHandler(dataProtector);
        }

        protected override AuthenticationHandler<TOptions> CreateHandler()
        {
            return new THandler { Logger = logger };
        }
    }
}