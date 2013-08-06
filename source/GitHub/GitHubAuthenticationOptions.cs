namespace Community.Owin.Security.GitHub
{
    using System;

    using Microsoft.Owin.Security;

    public class GitHubAuthenticationOptions : AuthenticationOptions
    {
        public GitHubAuthenticationOptions(string clientId, string clientSecret) : base("GitHub")
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

            Caption = "GitHub";
            ReturnPath = "/signin-github";
            AuthenticationMode = AuthenticationMode.Passive;
        }

        public string ClientId { get; private set; }

        public string ClientSecret { get; private set; }

        public string Scope { get; set; }

        public string ReturnPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IGitHubAuthenticationProvider Provider { get; set; }

        public ISecureDataHandler<AuthenticationExtra> StateDataHandler
        {
            get;
            set;
        }

        public string Caption
        {
            get
            {
                return Description.Caption;
            }

            set
            {
                Description.Caption = value;
            }
        }
    }
}