namespace Community.Owin.Security
{
    using System;
    using System.Threading.Tasks;

    public class OAuth2AuthenticationProvider : IOAuth2AuthenticationProvider
    {
        public OAuth2AuthenticationProvider()
        {
            #pragma warning disable 1998
            OnAuthenticated = async context => { };
            OnReturnEndpoint = async context => { };
            #pragma warning restore 1998
        }

        public Func<OAuth2AuthenticatedContext, Task> OnAuthenticated
        {
            get; set;
        }

        public Func<OAuth2ReturnEndpointContext, Task> OnReturnEndpoint
        {
            get; set;
        }

        public virtual Task Authenticated(OAuth2AuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(OAuth2ReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}