using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using MinecraftFirewall.Proxy.Admin;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Verifies the admin pipe's access control at the ACL-construction level. This does NOT prove a
/// real non-elevated process is refused at connect time — that would require spawning an actual
/// non-admin process, which this environment can't script — so treat that end-to-end behavior as
/// unverified, not proven, until it's exercised for real (see docs/plan.md).
/// </summary>
public class AdminAclTests
{
    [Fact]
    public void BuildAdministratorsOnlyAcl_GrantsExactlyOneExplicitRule_ForAdministratorsOnly()
    {
        var security = AdminPipeServer.BuildAdministratorsOnlyAcl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));

        Assert.Single(rules.Cast<PipeAccessRule>());

        var rule = rules.Cast<PipeAccessRule>().Single();
        var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        Assert.Equal(administratorsSid, rule.IdentityReference);
        Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
        Assert.True(rule.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite));
    }

    [Fact]
    public void BuildAdministratorsOnlyAcl_DoesNotGrantEveryoneOrAuthenticatedUsers()
    {
        var security = AdminPipeServer.BuildAdministratorsOnlyAcl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>();

        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);

        Assert.DoesNotContain(rules, r => r.IdentityReference == everyone);
        Assert.DoesNotContain(rules, r => r.IdentityReference == authenticatedUsers);
    }
}
