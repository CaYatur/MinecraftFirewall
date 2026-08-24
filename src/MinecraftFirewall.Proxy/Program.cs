using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.RateLimiting;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "MinecraftFirewall.Proxy");

builder.Services.AddSerilog((services, loggerConfiguration) => loggerConfiguration
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

builder.Services.Configure<VpnIntelOptions>(builder.Configuration.GetSection(VpnIntelOptions.SectionName));
builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection(RateLimitOptions.SectionName));
builder.Services.Configure<FirewallBanOptions>(builder.Configuration.GetSection(FirewallBanOptions.SectionName));
builder.Services.Configure<NeverBanOptions>(builder.Configuration.GetSection(NeverBanOptions.SectionName));
builder.Services.Configure<IdentityOptions>(builder.Configuration.GetSection(IdentityOptions.SectionName));
builder.Services.Configure<DangerousCommandOptions>(builder.Configuration.GetSection(DangerousCommandOptions.SectionName));
builder.Services.Configure<MessagesOptions>(builder.Configuration.GetSection(MessagesOptions.SectionName));

builder.Services.AddHttpClient();

builder.Services.AddSingleton<VpnIntelligence>();
builder.Services.AddSingleton<ConnectionRateLimiter>();
builder.Services.AddSingleton<NeverBanList>();
builder.Services.AddSingleton<IWindowsFirewallGateway, WindowsFirewallGateway>();
builder.Services.AddSingleton<FirewallBanService>();
builder.Services.AddSingleton<StrikeTracker>();
builder.Services.AddSingleton<PolicyEngine>();

var profileConfigs = builder.Configuration.GetSection("ServerProfiles").Get<List<ServerProfileConfig>>() ?? [];
var profiles = ServerProfileFactory.Build(profileConfigs);
builder.Services.AddSingleton<IReadOnlyList<ServerProfile>>(profiles);

builder.Services.AddHostedService<IpListRefreshService>();
builder.Services.AddHostedService<ProxyHostService>();

var host = builder.Build();
host.Run();
