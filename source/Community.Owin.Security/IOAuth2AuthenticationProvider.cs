namespace Community.Owin.Security
{
    using System.Threading.Tasks;

    public interface IOAuth2AuthenticationProvider
    {
        Task Authenticated(OAuth2AuthenticatedContext context);

        Task ReturnEndpoint(OAuth2ReturnEndpointContext context);
    }
}