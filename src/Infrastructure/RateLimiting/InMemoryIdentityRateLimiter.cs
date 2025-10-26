using Application.Abstractions.Services;
using Application.Identity.RateLimiting;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Infrastructure.RateLimiting;

internal sealed class InMemoryIdentityRateLimiter : IIdentityRateLimiter
{
    private static readonly TimeSpan RegisterWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan LoginAccountWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan LoginIpWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan TwoFactorWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan LogoutWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PasswordRotateVerifyWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan PasswordRotateWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan ForgotPasswordWindow = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ForgotPasswordDailyWindow = TimeSpan.FromDays(1);
    private static readonly TimeSpan ResetPasswordTokenWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan ResetPasswordAccountWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan TwoFactorEmailWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan TwoFactorEmailDailyWindow = TimeSpan.FromDays(1);

    private readonly IMemoryCache _cache;
    private readonly IDateTimeProvider _clock;
    private readonly ILogger<InMemoryIdentityRateLimiter> _logger;

    public InMemoryIdentityRateLimiter(IMemoryCache cache, IDateTimeProvider clock, ILogger<InMemoryIdentityRateLimiter> logger)
    {
        _cache = cache;
        _clock = clock;
        _logger = logger;
    }

    public Task<RateLimitOutcome> EnforceRegisterAsync(RegisterRateLimitContext context, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var requireCaptcha = false;

        if (!string.IsNullOrWhiteSpace(context.IpAddress))
        {
            var ipKey = $"register:ip:{context.IpAddress}";
            var ipState = GetSlidingState(ipKey);
            var ipAttempts = ipState.GetCount(now, RegisterWindow) + 1;
            ipState.Add(now, RegisterWindow);

            if (!GetTokenBucketState($"register:bucket:{context.IpAddress}").TryConsume(now, capacity: 2, refillPeriod: TimeSpan.FromMinutes(12)))
            {
                _logger.LogWarning("Register IP token bucket depleted for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromMinutes(15)));
            }

            if (ipAttempts > 5)
            {
                _logger.LogWarning("Register per-IP limit exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromHours(1)));
            }

            if (ipAttempts > 3)
            {
                requireCaptcha = true;
            }
        }

        if (!string.IsNullOrWhiteSpace(context.Asn))
        {
            var asnKey = $"register:asn:{context.Asn}";
            var asnState = GetSlidingState(asnKey);
            var asnAttempts = asnState.GetCount(now, RegisterWindow) + 1;
            asnState.Add(now, RegisterWindow);

            if (asnAttempts > 3)
            {
                _logger.LogWarning("Register per-ASN limit exceeded for {Asn}", context.Asn);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromHours(1)));
            }
        }

        if (!string.IsNullOrWhiteSpace(context.EmailDomain) && !string.IsNullOrWhiteSpace(context.TenantId))
        {
            var domainKey = $"register:domain:{context.TenantId}:{context.EmailDomain}";
            var domainState = GetSlidingState(domainKey);
            var domainAttempts = domainState.GetCount(now, RegisterWindow) + 1;
            domainState.Add(now, RegisterWindow);

            if (domainAttempts > 20)
            {
                _logger.LogWarning("Register per-domain limit exceeded for {Domain} in tenant {Tenant}", context.EmailDomain, context.TenantId);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromHours(1)));
            }
        }

        if (context.IsDisposableDomain)
        {
            _logger.LogWarning("Register attempt blocked due to disposable domain {Domain}", context.EmailDomain);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromHours(1)));
        }

        if (requireCaptcha)
        {
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromMinutes(15)));
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> CheckLoginAsync(LoginRateLimitContext context, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var lockState = GetSoftLockState($"login:softlock:{context.NormalizedEmail}");
        if (lockState.IsLocked(now))
        {
            var remaining = lockState.LockedUntil - now;
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.SoftLock, remaining, remaining));
        }

        if (context.IsHighRisk)
        {
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.StepUpMfa));
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterLoginResultAsync(LoginRateLimitContext context, LoginAttemptOutcome outcome, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var accountKey = $"login:account:{context.NormalizedEmail}";
        var deviceKey = !string.IsNullOrWhiteSpace(context.DeviceId) ? $"login:device:{context.DeviceId}" : null;
        var ipKey = !string.IsNullOrWhiteSpace(context.IpAddress) ? $"login:ip:{context.IpAddress}" : null;

        var accountLimit = context.IsHighRisk ? 5 : 10;
        var delayThreshold = context.IsHighRisk ? 3 : 5;
        var deviceLimit = context.IsHighRisk ? 10 : 20;
        var ipLimit = context.IsHighRisk ? 50 : 100;

        if (outcome == LoginAttemptOutcome.Success)
        {
            GetSlidingState(accountKey).Clear();
            if (deviceKey is not null)
            {
                GetSlidingState(deviceKey).Clear();
            }

            return Task.FromResult(RateLimitOutcome.Allowed());
        }

        if (outcome == LoginAttemptOutcome.RequiresTwoFactor)
        {
            return Task.FromResult(RateLimitOutcome.Allowed());
        }

        if (outcome == LoginAttemptOutcome.LockedOut)
        {
            var lockState = GetSoftLockState($"login:softlock:{context.NormalizedEmail}");
            var duration = TimeSpan.FromMinutes(15);
            lockState.LockUntil(now.Add(duration));
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.SoftLock, duration, duration));
        }

        // Failed credentials
        var accountState = GetSlidingState(accountKey);
        var attemptsAfter = accountState.GetCount(now, LoginAccountWindow) + 1;
        accountState.Add(now, LoginAccountWindow);

        if (attemptsAfter >= accountLimit)
        {
            var lockState = GetSoftLockState($"login:softlock:{context.NormalizedEmail}");
            var duration = TimeSpan.FromMinutes(15);
            lockState.LockUntil(now.Add(duration));
            _logger.LogWarning("Login soft lock applied for account {Account}", context.NormalizedEmail);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.SoftLock, duration, duration));
        }

        if (ipKey is not null)
        {
            var ipState = GetSlidingState(ipKey);
            var ipAfter = ipState.GetCount(now, LoginIpWindow) + 1;
            ipState.Add(now, LoginIpWindow);
            if (ipAfter > ipLimit)
            {
                _logger.LogWarning("Login IP limit exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromHours(1)));
            }
        }

        if (deviceKey is not null)
        {
            var deviceState = GetSlidingState(deviceKey);
            var deviceAfter = deviceState.GetCount(now, TimeSpan.FromHours(1)) + 1;
            deviceState.Add(now, TimeSpan.FromHours(1));
            if (deviceAfter > deviceLimit)
            {
                _logger.LogWarning("Login device limit exceeded for {Device}", context.DeviceId);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromHours(1)));
            }
        }

        if (attemptsAfter >= delayThreshold)
        {
            var delayMs = Random.Shared.Next(500, 1501);
            return Task.FromResult(RateLimitOutcome.Allowed(TimeSpan.FromMilliseconds(delayMs)));
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterTwoFactorAttemptAsync(TwoFactorRateLimitContext context, bool succeeded, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var challengeKey = $"2fa:challenge:{context.ChallengeKey}";
        var accountKey = $"2fa:account:{context.AccountKey}";
        var ipKey = !string.IsNullOrWhiteSpace(context.IpAddress) ? $"2fa:ip:{context.IpAddress}" : null;

        var challengeState = GetFixedState(challengeKey);
        var challengeAfter = challengeState.Increment(now, TwoFactorWindow);
        if (challengeAfter > 5)
        {
            _logger.LogWarning("Two-factor challenge exhausted for {Challenge}", context.ChallengeKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RegenerateChallenge, TimeSpan.FromMinutes(10)));
        }

        if (ipKey is not null)
        {
            var ipState = GetFixedState(ipKey);
            var ipAfter = ipState.Increment(now, TwoFactorWindow);
            if (ipAfter > 50)
            {
                _logger.LogWarning("Two-factor IP limit exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromMinutes(10)));
            }
        }

        if (!succeeded)
        {
            var errorState = GetSlidingState($"2fa:errors:{context.ChallengeKey}");
            var errorAfter = errorState.GetCount(now, TwoFactorWindow) + 1;
            errorState.Add(now, TwoFactorWindow);
            if (errorAfter >= 3)
            {
                var delayMs = Random.Shared.Next(500, 1501);
                return Task.FromResult(RateLimitOutcome.Allowed(TimeSpan.FromMilliseconds(delayMs)));
            }
        }
        else
        {
            GetSlidingState($"2fa:errors:{context.ChallengeKey}").Clear();
            GetFixedState(accountKey).Reset(now);
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterRefreshAttemptAsync(RefreshRateLimitContext context, bool success, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var sessionKey = $"refresh:session:{context.SessionKey}";
        var accountKey = $"refresh:account:{context.AccountKey}";

        var bucket = GetTokenBucketState(sessionKey);
        if (!bucket.TryConsume(now, capacity: 3, refillPeriod: TimeSpan.FromSeconds(30)))
        {
            _logger.LogWarning("Refresh token bucket exhausted for session {Session}", context.SessionKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RevokeToken, TimeSpan.FromMinutes(5)));
        }

        if (success)
        {
            var accountState = GetSlidingState(accountKey);
            var after = accountState.GetCount(now, TimeSpan.FromMinutes(10)) + 1;
            accountState.Add(now, TimeSpan.FromMinutes(10));
            if (after > 60)
            {
                _logger.LogWarning("Refresh per-account limit exceeded for {Account}", context.AccountKey);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromMinutes(10)));
            }
        }

        if (!success)
        {
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RevokeToken, TimeSpan.FromMinutes(5)));
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterLogoutAttemptAsync(SimpleRateLimitContext context, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var accountKey = context.AccountKey is not null ? $"logout:account:{context.AccountKey}" : null;
        var ipKey = context.IpAddress is not null ? $"logout:ip:{context.IpAddress}" : null;

        if (accountKey is not null)
        {
            var accountState = GetFixedState(accountKey);
            var accountAfter = accountState.Increment(now, LogoutWindow);
            if (accountAfter > 30)
            {
                _logger.LogWarning("Logout per-account limit exceeded for {Account}", context.AccountKey);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromMinutes(5)));
            }
        }

        if (ipKey is not null)
        {
            var ipState = GetFixedState(ipKey);
            var ipAfter = ipState.Increment(now, LogoutWindow);
            if (ipAfter > 30)
            {
                _logger.LogWarning("Logout per-IP limit exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromMinutes(5)));
            }
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterPasswordRotateAttemptAsync(PasswordRotateRateLimitContext context, PasswordRotateAttemptType attemptType, bool succeeded, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var verifyKey = $"pwd-rotate:verify:{context.AccountKey}";
        var rotateKey = $"pwd-rotate:rotate:{context.AccountKey}";
        var lockState = GetSoftLockState($"pwd-rotate:lock:{context.AccountKey}");

        if (lockState.IsLocked(now))
        {
            var remaining = lockState.LockedUntil - now;
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.SoftLock, remaining, remaining));
        }

        if (attemptType == PasswordRotateAttemptType.VerifyCurrentPassword)
        {
            if (succeeded)
            {
                GetSlidingState(verifyKey).Clear();
                return Task.FromResult(RateLimitOutcome.Allowed());
            }

            var state = GetSlidingState(verifyKey);
            var after = state.GetCount(now, PasswordRotateVerifyWindow) + 1;
            state.Add(now, PasswordRotateVerifyWindow);

            if (after >= 5)
            {
                var duration = TimeSpan.FromMinutes(15);
                lockState.LockUntil(now.Add(duration));
                _logger.LogWarning("Password rotate verification soft lock for {Account}", context.AccountKey);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.SoftLock, duration, duration));
            }

            if (after >= 3)
            {
                var delayMs = Random.Shared.Next(500, 1501);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromMinutes(15)));
            }

            return Task.FromResult(RateLimitOutcome.Allowed());
        }

        if (!succeeded)
        {
            return Task.FromResult(RateLimitOutcome.Allowed());
        }

        var rotateState = GetSlidingState(rotateKey);
        var rotateAfter = rotateState.GetCount(now, PasswordRotateWindow) + 1;
        rotateState.Add(now, PasswordRotateWindow);
        if (rotateAfter > 3)
        {
            _logger.LogWarning("Password rotate limit exceeded for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromHours(1)));
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterForgotPasswordSendAsync(ForgotPasswordRateLimitContext context, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var accountKey = $"forgot:account:{context.AccountKey}";
        var accountDailyKey = $"forgot:account:daily:{context.AccountKey}";
        var ipKey = context.IpAddress is not null ? $"forgot:ip:{context.IpAddress}" : null;
        var ipDailyKey = context.IpAddress is not null ? $"forgot:ip:daily:{context.IpAddress}" : null;
        var tenantKey = context.TenantId is not null ? $"forgot:tenant:{context.TenantId}" : null;

        var accountWindowState = GetFixedState(accountKey);
        var accountAfter = accountWindowState.Increment(now, ForgotPasswordWindow);
        if (accountAfter > 3)
        {
            _logger.LogWarning("Forgot-password per-account limit exceeded for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromMinutes(30)));
        }

        var accountDailyState = GetFixedState(accountDailyKey);
        var accountDailyAfter = accountDailyState.Increment(now, ForgotPasswordDailyWindow);
        if (accountDailyAfter > 5)
        {
            _logger.LogWarning("Forgot-password daily cap exceeded for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromDays(1)));
        }

        if (ipKey is not null)
        {
            var ipState = GetFixedState(ipKey);
            var ipAfter = ipState.Increment(now, TimeSpan.FromHours(1));
            if (ipAfter > 20)
            {
                _logger.LogWarning("Forgot-password per-IP limit exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromHours(1)));
            }
        }

        if (ipDailyKey is not null)
        {
            var ipDailyState = GetFixedState(ipDailyKey);
            var ipDailyAfter = ipDailyState.Increment(now, ForgotPasswordDailyWindow);
            if (ipDailyAfter > 50)
            {
                _logger.LogWarning("Forgot-password daily per-IP cap exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.Block, TimeSpan.FromDays(1)));
            }
        }

        if (tenantKey is not null)
        {
            var tenantState = GetFixedState(tenantKey);
            tenantState.Increment(now, ForgotPasswordWindow);
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterForgotPasswordVerifyAsync(VerifyResetRateLimitContext context, bool succeeded, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var flowKey = $"reset-verify:flow:{context.FlowKey}";
        var ipKey = context.IpAddress is not null ? $"reset-verify:ip:{context.IpAddress}" : null;

        var flowState = GetFixedState(flowKey);
        var flowAfter = flowState.Increment(now, TwoFactorWindow);
        if (flowAfter > 5)
        {
            _logger.LogWarning("Reset-code flow invalidated for {Flow}", context.FlowKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RegenerateChallenge, TimeSpan.FromMinutes(10)));
        }

        if (ipKey is not null)
        {
            var ipState = GetFixedState(ipKey);
            var ipAfter = ipState.Increment(now, TwoFactorWindow);
            if (ipAfter > 50)
            {
                _logger.LogWarning("Reset-code IP limit exceeded for {Ip}", context.IpAddress);
                return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromMinutes(10)));
            }
        }

        if (!succeeded)
        {
            var errorState = GetSlidingState($"reset-verify:errors:{context.FlowKey}");
            var errorAfter = errorState.GetCount(now, TwoFactorWindow) + 1;
            errorState.Add(now, TwoFactorWindow);
            if (errorAfter >= 3)
            {
                var delayMs = Random.Shared.Next(500, 1501);
                return Task.FromResult(RateLimitOutcome.Allowed(TimeSpan.FromMilliseconds(delayMs)));
            }
        }
        else
        {
            GetSlidingState($"reset-verify:errors:{context.FlowKey}").Clear();
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterResetPasswordAsync(ResetPasswordRateLimitContext context, bool succeeded, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var tokenKey = $"reset:token:{context.TokenKey}";
        var accountKey = $"reset:account:{context.AccountKey}";

        var tokenState = GetSlidingState(tokenKey);
        var tokenAfter = tokenState.GetCount(now, ResetPasswordTokenWindow) + 1;
        tokenState.Add(now, ResetPasswordTokenWindow);
        if (tokenAfter > 3)
        {
            _logger.LogWarning("Reset token invalidated for {Token}", context.TokenKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RegenerateChallenge, TimeSpan.FromMinutes(15)));
        }

        var accountState = GetSlidingState(accountKey);
        var accountAfter = accountState.GetCount(now, ResetPasswordAccountWindow) + 1;
        accountState.Add(now, ResetPasswordAccountWindow);
        if (accountAfter > 5)
        {
            _logger.LogWarning("Reset password per-account limit exceeded for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromHours(1)));
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterTwoFactorEmailGenerateAsync(TwoFactorEmailRateLimitContext context, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var key = $"2fa-email:generate:{context.AccountKey}";
        var dailyKey = $"2fa-email:generate:daily:{context.AccountKey}";
        var ipKey = context.IpAddress is not null ? $"2fa-email:ip:{context.IpAddress}" : null;

        var state = GetFixedState(key);
        var after = state.Increment(now, TwoFactorEmailWindow);
        if (after > 3)
        {
            _logger.LogWarning("2FA email generate limit exceeded for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TwoFactorEmailWindow));
        }

        var dailyState = GetFixedState(dailyKey);
        var dailyAfter = dailyState.Increment(now, TwoFactorEmailDailyWindow);
        if (dailyAfter > 10)
        {
            _logger.LogWarning("2FA email generate daily cap exceeded for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RequireCaptcha, TimeSpan.FromDays(1)));
        }

        if (ipKey is not null)
        {
            GetFixedState(ipKey).Increment(now, TwoFactorEmailWindow);
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    public Task<RateLimitOutcome> RegisterTwoFactorEmailEnableAsync(TwoFactorEmailRateLimitContext context, bool succeeded, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var key = $"2fa-email:enable:{context.AccountKey}";
        var state = GetFixedState(key);
        var after = state.Increment(now, TwoFactorWindow);
        if (after > 5)
        {
            _logger.LogWarning("2FA email enable attempts exhausted for {Account}", context.AccountKey);
            return Task.FromResult(RateLimitOutcome.Blocked(IdentityRateLimitAction.RegenerateChallenge, TimeSpan.FromMinutes(10)));
        }

        if (succeeded)
        {
            state.Reset(now);
        }

        return Task.FromResult(RateLimitOutcome.Allowed());
    }

    private SlidingWindowState GetSlidingState(string key)
    {
        return _cache.GetOrCreate(key, entry =>
        {
            entry.SetSlidingExpiration(TimeSpan.FromHours(24));
            return new SlidingWindowState();
        })!;
    }

    private FixedWindowState GetFixedState(string key)
    {
        return _cache.GetOrCreate(key, entry =>
        {
            entry.SetSlidingExpiration(TimeSpan.FromHours(24));
            return new FixedWindowState();
        })!;
    }

    private TokenBucketState GetTokenBucketState(string key)
    {
        return _cache.GetOrCreate(key, entry =>
        {
            entry.SetSlidingExpiration(TimeSpan.FromHours(1));
            return new TokenBucketState();
        })!;
    }

    private SoftLockState GetSoftLockState(string key)
    {
        return _cache.GetOrCreate(key, entry =>
        {
            entry.SetSlidingExpiration(TimeSpan.FromHours(1));
            return new SoftLockState();
        })!;
    }
}
