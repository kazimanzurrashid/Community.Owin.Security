namespace Community.Owin.Security.GitHub
{
    using System;
    using System.IO;
    using System.Net;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Helpers;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    using Newtonsoft.Json.Linq;

    internal class GitHubAuthenticationHandler :
        AuthenticationHandler<GitHubAuthenticationOptions>
    {
        private readonly ILogger logger;

        public GitHubAuthenticationHandler(ILogger logger)
        {
            this.logger = logger;
        }

        public override async Task<bool> Invoke()
        {
            if (Options.ReturnPath != null &&
                Options.ReturnPath.Equals(Request.Path, StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPath();
            }

            return false;
        }

        public async Task<bool> InvokeReturnPath()
        {
            logger.WriteVerbose("InvokeReturnPath");

            var authenticationTicket = await Authenticate();

            var returnEndpointContext = new GitHubReturnEndpointContext(
                Request.Environment,
                authenticationTicket,
                ErrorDetails)
                {
                    SignInAsAuthenticationType = Options
                        .SignInAsAuthenticationType,

                    RedirectUri = authenticationTicket.Extra
                        .RedirectUrl
                };

            authenticationTicket.Extra.RedirectUrl = null;

            await Options.Provider.ReturnEndpoint(returnEndpointContext);

            if (returnEndpointContext.SignInAsAuthenticationType != null &&
                returnEndpointContext.Identity != null)
            {
                var identity = returnEndpointContext.Identity;

                if (!string.Equals(
                    identity.AuthenticationType,
                    returnEndpointContext.SignInAsAuthenticationType,
                    StringComparison.Ordinal))
                {
                    identity = new ClaimsIdentity(
                        identity.Claims,
                        returnEndpointContext.SignInAsAuthenticationType,
                        identity.NameClaimType,
                        identity.RoleClaimType);
                }

                Response.Grant(identity, returnEndpointContext.Extra);
            }

            if (!returnEndpointContext.IsRequestCompleted &&
                returnEndpointContext.RedirectUri != null)
            {
                Response.Redirect(returnEndpointContext.RedirectUri);
                returnEndpointContext.RequestCompleted();
            }

            var isRequestCompleted = returnEndpointContext.IsRequestCompleted;

            return isRequestCompleted;
        }

        #pragma warning disable 1998
        protected override async Task ApplyResponseChallenge()
        #pragma warning restore 1998
        {
            logger.WriteVerbose("ApplyResponseChallenge");

            if (Response.StatusCode != 401)
            {
                return;
            }

            var challenge = Helper.LookupChallenge(
                Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null)
            {
                return;
            }

            var requestPrefix = Request.Scheme + "://" + Request.Host;
            var currentQueryString = Request.QueryString;

            var currentUri = string.IsNullOrEmpty(currentQueryString) ?
                requestPrefix + Request.PathBase + Request.Path :
                requestPrefix + Request.PathBase + Request.Path + "?" + currentQueryString;

            var redirectUri = requestPrefix + Request.PathBase + Options.ReturnPath;

            var extra = challenge.Extra;
            if (string.IsNullOrEmpty(extra.RedirectUrl))
            {
                extra.RedirectUrl = currentUri;
            }

            GenerateCorrelationId(extra);

            var state = Options.StateDataHandler.Protect(extra);

            var authorizationEndpoint =
                "https://github.com/login/oauth/authorize" +
                    "?response_type=code" +
                    "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&scope=" + Uri.EscapeDataString(Options.Scope ?? string.Empty) +
                    "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCore()
        {
            logger.WriteVerbose("AuthenticateCore");
            AuthenticationExtra extra = null;

            try
            {
                var query = this.Request.GetQuery();
                string[] lookup;
                string code = null;
                string state = null;

                if (query.TryGetValue("code", out lookup) &&
                    lookup != null &&
                    lookup.Length == 1)
                {
                    code = lookup[0];
                }

                if (code == null)
                {
                    return null;
                }

                if (query.TryGetValue("state", out lookup) &&
                    lookup != null &&
                    lookup.Length == 1)
                {
                    state = lookup[0];
                }

                extra = Options.StateDataHandler.Unprotect(state);

                if (extra == null)
                {
                    return null;
                }

                if (ValidateCorrelationId(extra, logger))
                {
                    var accessToken = await this.GetAccessToken(code);

                    if (accessToken != null)
                    {
                        var user = await GetUserInfo(accessToken);

                        var authenticatedContext = new GitHubAuthenticatedContext(
                            accessToken,
                            user.Item1,
                            user.Item2,
                            Request.Environment)
                            {
                                Identity = new ClaimsIdentity(
                                    Options.AuthenticationType,
                                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"),
                                    Extra = extra
                            };

                        if (!string.IsNullOrWhiteSpace(authenticatedContext.UserId))
                        {
                            authenticatedContext.Identity.AddClaim(
                                new Claim(
                                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", 
                                    authenticatedContext.UserId, 
                                    "http://www.w3.org/2001/XMLSchema#string",
                                    Options.AuthenticationType));
                        }

                        if (!string.IsNullOrWhiteSpace(authenticatedContext.UserName))
                        {
                            authenticatedContext.Identity.AddClaim(
                                new Claim(
                                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                                    authenticatedContext.UserName,
                                    "http://www.w3.org/2001/XMLSchema#string",
                                    Options.AuthenticationType));
                        }

                        await Options.Provider.Authenticated(authenticatedContext);

                        return new AuthenticationTicket(
                            authenticatedContext.Identity,
                            authenticatedContext.Extra);
                    }
                }
            }
            catch (Exception e)
            {
                logger.WriteError(e.Message);
            }

            return new AuthenticationTicket(null, extra);
        }

        private static HttpWebRequest CreateWebRequest(string url)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);

            request.ProtocolVersion = HttpVersion.Version11;
            request.UserAgent = "katana twitter middleware";

            return request;
        }

        private static async Task<Tuple<string, string>> GetUserInfo(
            string accessToken)
        {
            var request = CreateWebRequest(
                "https://api.github.com/user?access_token=" +
                Uri.EscapeDataString(accessToken));

            request.Accept = "application/json,text/json";

            var response = await request.GetResponseAsync();
            var responseStream = response.GetResponseStream();

            if (responseStream == null)
            {
                return null;
            }

            JObject json;

            using (var reader = new StreamReader(responseStream))
            {
                var body = await reader.ReadToEndAsync();
                json = JObject.Parse(body);
            }

            return new Tuple<string, string>(
                (string)json["id"],
                (string)json["login"]);
        }

        private async Task<string> GetAccessToken(string code)
        {
            var parts = new[]
            {
                "code=", 
                Uri.EscapeDataString(code),
                "&client_id=",
                Uri.EscapeDataString(Options.ClientId),
                "&client_secret=",
                Uri.EscapeDataString(Options.ClientSecret)
            };

            var request = CreateWebRequest(
                "https://github.com/login/oauth/access_token");

            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Accept = "*/*";

            var requestStream = await request.GetRequestStreamAsync();

            using (var writer = new StreamWriter(requestStream))
            {
                await writer.WriteAsync(string.Concat(parts));
            }

            var response = await request.GetResponseAsync();
            var responseStream = response.GetResponseStream();

            if (responseStream == null)
            {
                return null;
            }

            string body;

            using (var reader = new StreamReader(responseStream))
            {
                body = await reader.ReadToEndAsync();
            }

            var content = WebHelpers.ParseNameValueCollection(body);
            var accessToken = content["access_token"];

            return accessToken;
        }
    }
}