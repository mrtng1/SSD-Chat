using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Components;

namespace ChatFrontend.Services
{
    public class AuthService : AuthenticationStateProvider
    {
        private readonly HttpClient _http;
        private readonly IJSRuntime _js;
        private readonly NavigationManager _nav;

        public AuthService(HttpClient http, IJSRuntime js, NavigationManager nav)
        {
            _http = http;
            _js = js;
            _nav = nav;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = await GetTokenAsync();
        
            if (string.IsNullOrEmpty(token) || !IsTokenValid(token))
            {
                //await Logout();
                return new AuthenticationState(new ClaimsPrincipal());
            }

            return CreateStateFromToken(token);
        }
        
        private bool IsTokenValid(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(token);
            
                if (jwt.ValidTo < DateTime.UtcNow)
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<string> GetTokenAsync()
        {
            try
            {
                return await _js.InvokeAsync<string>("localStorage.getItem", "authToken");
            }
            catch
            {
                return null;
            }
        }

        public async Task Login(string token)
        {
            await _js.InvokeVoidAsync("localStorage.setItem", "authToken", token);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async Task Logout()
        {
            await _js.InvokeVoidAsync("localStorage.removeItem", "authToken");
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            _nav.NavigateTo("/login");
        }

        private AuthenticationState CreateStateFromToken(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(token);
                var identity = new ClaimsIdentity(jwt.Claims, "jwt");
                return new AuthenticationState(new ClaimsPrincipal(identity));
            }
            catch
            {
                // Return anonymous state when token is invalid
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }
        }

        
    }
}
