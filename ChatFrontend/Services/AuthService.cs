using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using ChatFrontend.DTOs;
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
            var token = await _js.InvokeAsync<string>("localStorage.getItem", "authToken");
            if (string.IsNullOrEmpty(token))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var claims = jwtToken.Claims.ToList();

            // Extract existing claims from the JWT
            var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            var username = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName)?.Value;

            // Add or replace custom claims
            claims.Add(new Claim("JWT", token));
            claims.Add(new Claim("UserId", userId ?? string.Empty));
            claims.Add(new Claim("Username", username ?? string.Empty));

            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            return new AuthenticationState(user);
        }
        
        public async Task<bool> IsTokenValid(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
        
                // Basic client-side validation
                if (!handler.CanReadToken(token)) return false;
        
                var jwt = handler.ReadJwtToken(token);
                var expiry = jwt.ValidTo.ToUniversalTime();
        
                // Check expiration with 1 minute buffer
                if (expiry < DateTime.UtcNow.AddMinutes(-1))
                {
                    await Logout();
                    return false;
                }

                return true;
            }
            catch
            {
                await Logout();
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
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            
            var jwtToken = handler.ReadJwtToken(token);
            
            var claims = jwtToken.Claims.ToList();
            claims.Add(new Claim("JWT", token));

            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
    
            await _js.InvokeVoidAsync("localStorage.setItem", "authToken", token);
            CreateStateFromToken(token);
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
