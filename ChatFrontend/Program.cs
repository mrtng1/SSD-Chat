using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using ChatFrontend;
using ChatFrontend.Services;
using Microsoft.AspNetCore.Components.Authorization;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, AuthService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped(sp => new HttpClient 
    
{ 
    //BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) 
    BaseAddress = new Uri("http://localhost:5065")
});

await builder.Build().RunAsync();