namespace Community.Owin.Security
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

    public abstract class OAuth2AuthenticationHandler<TOptions> :
        AuthenticationHandler<TOptions> where TOptions: OAuth2AuthenticationOptions
    {
        protected OAuth2AuthenticationHandler(
            string codeEndpoint,
            string accessTokenEndpoint)
        {
            CodeEndpoint = codeEndpoint;
            AccessTokenEndpoint = accessTokenEndpoint;
        }

        public ILogger Logger { get; set; }

        protected string CodeEndpoint { get; private set; }

        protected string AccessTokenEndpoint { get; private set; }

        protected abstract string UserInfoEndpoint { get; }

        public override async Task<bool> Invoke()
        {
            if (Options.ReturnPath != null &&
                Options.ReturnPath.Equals(
                    Request.Path,
                    StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPath();
            }

            return false;
        }

        protected abstract OAuth2UserInfo ParseUserInfo(string content);

        protected virtual async Task<string> GetAccessToken(string code)
        {
            var requestPrefix = Request.Scheme + "://" + Request.Host;
            var redirectUri = requestPrefix + Request.PathBase + Options.ReturnPath;

            var parts = new[]
            {
                "client_id=",
                Uri.EscapeDataString(Options.ClientId),
                "&client_secret=",
                Uri.EscapeDataString(Options.ClientSecret),
                "&code=", 
                Uri.EscapeDataString(code),
                "&redirect_uri=", 
                Uri.EscapeDataString(redirectUri)
            };

            var request = CreateWebRequest(AccessTokenEndpoint);

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

        protected virtual async Task<OAuth2UserInfo> GetUserInfo(
            string accessToken)
        {
            var endpoint = UserInfoEndpoint +
                (UserInfoEndpoint.Contains("?") ?
                "&" :
                "?") +
                "access_token=" +
                Uri.EscapeDataString(accessToken);

            var request = CreateWebRequest(endpoint);

            request.Accept = "application/json,text/json";

            try
            {
                var response = await request.GetResponseAsync();
                var responseStream = response.GetResponseStream();

                if (responseStream == null)
                {
                    return null;
                }

                string content;

                using (var reader = new StreamReader(responseStream))
                {
                    content = await reader.ReadToEndAsync();
                }

                return ParseUserInfo(content);
            }
            catch (WebException we)
            {
                var message = GetExceptionContent(we);

                throw new InvalidOperationException(message, we);
            }
        }

        #pragma warning disable 1998
        protected override async Task ApplyResponseChallenge()
        #pragma warning restore 1998
        {
            Logger.WriteVerbose("ApplyResponseChallenge");

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

            var authorizationEndpoint = CodeEndpoint +
                "?response_type=code" +
                "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&scope=" + Uri.EscapeDataString(Options.Scope ?? string.Empty) +
                "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCore()
        {
            Logger.WriteVerbose("AuthenticateCore");
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

                if (ValidateCorrelationId(extra, Logger))
                {
                    var accessToken = await GetAccessToken(code);

                    if (accessToken != null)
                    {
                        var userInfo = await GetUserInfo(accessToken);

                        var authenticatedContext = new OAuth2AuthenticatedContext(
                            accessToken,
                            userInfo.UserId,
                            userInfo.UserName,
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
                Logger.WriteError(e.Message);
            }

            return new AuthenticationTicket(null, extra);
        }

        private static HttpWebRequest CreateWebRequest(string url)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);

            request.ProtocolVersion = HttpVersion.Version11;
            request.AutomaticDecompression = DecompressionMethods.GZip |
                DecompressionMethods.Deflate;
            request.UserAgent = "katana community oauth2 client middleware";

            return request;
        }

        private static string GetExceptionContent(WebException e)
        {
            var stream = e.Response.GetResponseStream();

            if (stream == null)
            {
                return null;
            }

            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        private async Task<bool> InvokeReturnPath()
        {
            Logger.WriteVerbose("InvokeReturnPath");

            var authenticationTicket = await Authenticate();

            var returnEndpointContext = new OAuth2ReturnEndpointContext(
                Request.Environment,
                authenticationTicket,
                ErrorDetails)
                {
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                    RedirectUri = authenticationTicket.Extra.RedirectUrl
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
    }
}