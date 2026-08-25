using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Admin;
using MinecraftFirewall.Proxy.Alerts;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Persistence;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Options;
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
builder.Services.Configure<IpInfoOptions>(builder.Configuration.GetSection(IpInfoOptions.SectionName));
builder.Services.Configure<PremiumOptions>(builder.Configuration.GetSection(PremiumOptions.SectionName));
builder.Services.Configure<IdentityPersistenceOptions>(builder.Configuration.GetSection(IdentityPersistenceOptions.SectionName));
builder.Services.Configure<DdosOptions>(builder.Configuration.GetSection(DdosOptions.SectionName));
builder.Services.Configure<BotDefenseOptions>(builder.Configuration.GetSection(BotDefenseOptions.SectionName));
builder.Services.Configure<HoneypotOptions>(builder.Configuration.GetSection(HoneypotOptions.SectionName));
builder.Services.Configure<ThreatIntelOptions>(builder.Configuration.GetSection(ThreatIntelOptions.SectionName));
builder.Services.Configure<InspectionOptions>(builder.Configuration.GetSection(InspectionOptions.SectionName));

builder.Services.Configure<AlertOptions>(builder.Configuration.GetSection(AlertOptions.SectionName));

builder.Services.AddHttpClient();

// A no-op sender when no webhook is configured, so nothing spins up a queue or a background pump for
// a feature that isn't in use — and call sites never need a null check either way.
builder.Services.AddSingleton<IAlertSender>(sp =>
{
    var alertOptions = sp.GetRequiredService<IOptions<AlertOptions>>();
    return string.IsNullOrWhiteSpace(alertOptions.Value.DiscordWebhookUrl)
        ? new NullAlertSender()
        : new DiscordAlertSender(alertOptions, sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<ILogger<DiscordAlertSender>>());
});

builder.Services.AddSingleton<VpnIntelligence>();
builder.Services.AddSingleton<ThreatIntelligence>();
builder.Services.AddSingleton<ConnectionGovernor>();
builder.Services.AddSingleton<BotDetector>();
builder.Services.AddSingleton<IIpInfoClient, IpInfoClient>();

// One RSA keypair for the whole process, generated at startup — the same thing a real Notchian
// server does ("Generating keypair" appears once in its log, not per connection).
builder.Services.AddSingleton<RsaServerKeyPair>();
builder.Services.AddSingleton<IPremiumSessionClient, MojangSessionClient>();
builder.Services.AddSingleton<PremiumVerifier>();
builder.Services.AddSingleton<PremiumLoginHandshake>();
builder.Services.AddSingleton<ConnectionRateLimiter>();
builder.Services.AddSingleton<NeverBanList>();
builder.Services.AddSingleton<IWindowsFirewallGateway, WindowsFirewallGateway>();
builder.Services.AddSingleton<FirewallBanService>();
builder.Services.AddSingleton<StrikeTracker>();
builder.Services.AddSingleton<PolicyEngine>();

var profileConfigs = builder.Configuration.GetSection("ServerProfiles").Get<List<ServerProfileConfig>>() ?? [];
var profiles = ServerProfileFactory.Build(profileConfigs);
builder.Services.AddSingleton<IReadOnlyList<ServerProfile>>(profiles);

// Registered as itself too (not just IHostedService) so AdminCommandHandler can call RefreshNowAsync
// directly for the `reload` command.
builder.Services.AddSingleton<IpListRefreshService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<IpListRefreshService>());

// Registered BEFORE ProxyHostService so its StartAsync (which loads the persisted store) runs first —
// hosted services start in registration order, and a connection must never be evaluated against a
// half-loaded identity store.
builder.Services.AddSingleton<IdentityStatePersistence>();
builder.Services.AddHostedService<IdentityPersistenceService>();

builder.Services.AddHostedService<ProxyHostService>();

// After ProxyHostService, so the profiles it reads are already built and the honeypot can see which
// ports are genuinely spoken for before it tries to bind a decoy on one of them.
builder.Services.AddSingleton<ThreatFeedService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ThreatFeedService>());
builder.Services.AddHostedService<HoneypotService>();

builder.Services.AddSingleton<AdminCommandHandler>();
builder.Services.AddHostedService<AdminPipeServer>();

var host = builder.Build();
host.Run();
