namespace Community.Owin.Security
{
    using System.Collections.Generic;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class OAuth2ReturnEndpointContext : ReturnEndpointContext
    {
        public OAuth2ReturnEndpointContext(
            IDictionary<string, object> environment,
            AuthenticationTicket ticket,
            IDictionary<string, string> errorDetails) : 
            base(environment, ticket, errorDetails)
        {
        }
    }
}