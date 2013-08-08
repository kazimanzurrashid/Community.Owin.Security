namespace Community.Owin.Security
{
    using System;

    using Microsoft.Owin.Security;

    public class OAuth2AuthenticationOptions : AuthenticationOptions
    {
        public OAuth2AuthenticationOptions(
            string authenticationType,
            string caption,
            string clientId,
            string clientSecret)
            : base(authenticationType)
        {
            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentException("Client id is required.", "clientId");
            }

            if (string.IsNullOrWhiteSpace(clientSecret))
            {
                throw new ArgumentException("Client secret is required.", "clientSecret");
            }

            ClientId = clientId;
            ClientSecret = clientSecret;

            Caption = caption;
            ReturnPath = "/signin-" + authenticationType;
            AuthenticationMode = AuthenticationMode.Passive;
        }

        public string ClientId { get; private set; }

        public string ClientSecret { get; private set; }

        public string Scope { get; set; }

        public string ReturnPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IOAuth2AuthenticationProvider Provider { get; set; }

        public ISecureDataHandler<AuthenticationExtra> StateDataHandler
        {
            get;
            set;
        }

        public string Caption
        {
            get { return Description.Caption; }

            set { Description.Caption = value; }
        }
    }
}