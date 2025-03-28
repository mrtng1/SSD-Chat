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

//adds bearer to requests
builder.Services.AddScoped<AuthHeaderHandler>();
builder.Services.AddScoped(sp => {
    var authHandler = sp.GetRequiredService<AuthHeaderHandler>();
    authHandler.InnerHandler = new HttpClientHandler();
    return new HttpClient(authHandler) 
    { 
        BaseAddress = new Uri("http://localhost:5065")
    };
});

builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ChatService>();
builder.Services.AddScoped<EncryptionService>();
builder.Services.AddScoped(sp => new HttpClient 
    
{ 
    //BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) 
    BaseAddress = new Uri("http://localhost:5065")
});

await builder.Build().RunAsync();