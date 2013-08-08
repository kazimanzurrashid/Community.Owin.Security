namespace Community.Owin.Security
{
    using System;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using global::Owin;

    public class OAuth2AuthenticationMiddleware<THandler> :
        AuthenticationMiddleware<OAuth2AuthenticationOptions>
        where THandler : OAuth2AuthenticationHandler, new()
    {
        private readonly ILogger logger;

        public OAuth2AuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            OAuth2AuthenticationOptions options)
            : base(next, options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            logger = app.CreateLogger<OAuth2AuthenticationMiddleware<THandler>>();

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
                typeof(OAuth2AuthenticationMiddleware<THandler>).FullName,
                Options.AuthenticationType
            };

            var dataProtector = app.CreateDataProtecter(fullName);
            Options.StateDataHandler = new ExtraDataHandler(dataProtector);
        }

        protected override AuthenticationHandler<OAuth2AuthenticationOptions> CreateHandler()
        {
            return new THandler { Logger = logger };
        }
    }
}