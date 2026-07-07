-- Client self-serve onboarding OTPs: emailed one-time passcodes, valid 4 hours.
-- The store's /onboard/verify flow calls /api/v1/onboard/otp/{request,verify}.
CREATE TABLE IF NOT EXISTS onboard_otps (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL,
    code_hash   TEXT NOT NULL,          -- sha256(code); the raw code is only emailed
    token       TEXT,                   -- opaque onboarding session token, set on verify
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    attempts    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_onboard_otps_email_created
    ON onboard_otps (email, created_at DESC);
