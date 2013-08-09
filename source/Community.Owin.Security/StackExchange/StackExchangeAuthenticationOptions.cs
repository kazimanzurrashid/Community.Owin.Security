namespace Community.Owin.Security
{
    using System;

    public class StackExchangeAuthenticationOptions : OAuth2AuthenticationOptions
    {
        public StackExchangeAuthenticationOptions(
            string clientId,
            string clientSecret,
            string key,
            string site)
            : base("stackexchange", "StackExchange", clientId, clientSecret)
        {
            if (string.IsNullOrWhiteSpace("key"))
            {
                throw new ArgumentException("Key is required", "key");
            }

            if (string.IsNullOrWhiteSpace("site"))
            {
                throw new ArgumentException("Site is required", "site");
            }

            Key = key;
            Site = site;
        }

        public string Key { get; private set; }

        public string Site { get; private set; }
    }
}