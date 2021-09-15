using IdentityServer4.Models;
using IdentityServer4.Validation;

namespace IdentityServer
{
    public class UrlValidator : IRedirectUriValidator
    {
        public UrlValidator()
        {
        }

        public Task<bool> IsPostLogoutRedirectUriValidAsync(string requestedUri, Client client)
        {
            return Task.FromResult(client.PostLogoutRedirectUris.Contains(requestedUri));
        }

        public Task<bool> IsRedirectUriValidAsync(string requestedUri, Client client)
        {
            return Task.FromResult(client.RedirectUris.Contains(requestedUri));

        }
    }
}
