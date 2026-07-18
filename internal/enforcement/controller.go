// Package enforcement is the policy decision point for continuous enforcement:
// it turns a risk signal about a device into a network-plane action (RFC 5176
// CoA/Disconnect) via the RadSec kill switch. Posture drop is the first signal
// wired in; NDR/SWG detections, deception trips, etc. call the same seam.
package enforcement

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Enforcer is the network-plane kill switch (satisfied by the RadSec server via
// an adapter). acked reports whether the NAS ACKed; a NAK is (false, nil).
type Enforcer interface {
	Disconnect(ctx context.Context, sessionKey string) (acked bool, err error)
	Quarantine(ctx context.Context, sessionKey string, vlan int, acl string) (acked bool, err error)
}

// Action is what to do when a device becomes risky.
type Action string

const (
	ActionOff        Action = "off"        // observe only — no CoA (default)
	ActionQuarantine Action = "quarantine" // CoA to a restricted VLAN (contain, keep the session)
	ActionDisconnect Action = "disconnect" // hard cut the session
)

// errNoLiveSession lets the controller treat "device has no live NAS session" as
// a benign no-op rather than a failure. The RadSec server returns an error whose
// message contains this; we match on it to avoid importing radsec (cycle).
const noLiveSessionMarker = "no live NAS session"

// Controller decides and applies the response to a risk signal.
type Controller struct {
	enforcer       Enforcer
	action         Action
	quarantineVLAN int
	quarantineACL  string
	timeout        time.Duration
	logger         *zap.Logger
}

// NewController wires a controller. A nil enforcer or ActionOff makes every
// response a logged no-op, so it's always safe to call.
func NewController(enforcer Enforcer, action Action, quarantineVLAN int, quarantineACL string, logger *zap.Logger) *Controller {
	if action == "" {
		action = ActionOff
	}
	return &Controller{
		enforcer:       enforcer,
		action:         action,
		quarantineVLAN: quarantineVLAN,
		quarantineACL:  quarantineACL,
		timeout:        10 * time.Second,
		logger:         logger,
	}
}

// ConfigFromEnv reads POSTURE_COA_ACTION (off|quarantine|disconnect, default off),
// POSTURE_QUARANTINE_VLAN, and POSTURE_QUARANTINE_ACL.
func ConfigFromEnv(enforcer Enforcer, logger *zap.Logger) *Controller {
	action := Action(strings.ToLower(strings.TrimSpace(os.Getenv("POSTURE_COA_ACTION"))))
	switch action {
	case ActionQuarantine, ActionDisconnect, ActionOff:
	default:
		action = ActionOff
	}
	vlan, _ := strconv.Atoi(os.Getenv("POSTURE_QUARANTINE_VLAN"))
	return NewController(enforcer, action, vlan, os.Getenv("POSTURE_QUARANTINE_ACL"), logger)
}

// Enabled reports whether a non-off action with a usable enforcer is configured.
func (c *Controller) Enabled() bool {
	return c != nil && c.enforcer != nil && c.action != ActionOff
}

// RespondToRisk applies the configured action to the device's live NAS session.
// sessionKey is the RadSec session key (device CN). Safe to call in a goroutine
// with a background context; a device with no live session is a no-op. Returns
// whether an action was actually applied (ACKed by the NAS).
func (c *Controller) RespondToRisk(ctx context.Context, sessionKey, orgID, reason string) (bool, error) {
	if !c.Enabled() {
		if c != nil && c.logger != nil {
			c.logger.Info("enforcement: risk signal observed (action off — no CoA)",
				zap.String("device", sessionKey), zap.String("org_id", orgID), zap.String("reason", reason))
		}
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var acked bool
	var err error
	switch c.action {
	case ActionDisconnect:
		acked, err = c.enforcer.Disconnect(ctx, sessionKey)
	case ActionQuarantine:
		acked, err = c.enforcer.Quarantine(ctx, sessionKey, c.quarantineVLAN, c.quarantineACL)
	}

	if err != nil {
		if strings.Contains(err.Error(), noLiveSessionMarker) {
			// The device isn't attached to a NAS right now (e.g. it's off-network
			// on the tunnel). Nothing to cut; the drop is still recorded in posture.
			c.logger.Info("enforcement: risk signal but no live NAS session — nothing to cut",
				zap.String("device", sessionKey), zap.String("reason", reason))
			return false, nil
		}
		c.logger.Error("enforcement: CoA failed",
			zap.String("device", sessionKey), zap.String("action", string(c.action)),
			zap.String("reason", reason), zap.Error(err))
		return false, err
	}

	c.logger.Warn("enforcement: risk response applied",
		zap.String("device", sessionKey), zap.String("org_id", orgID),
		zap.String("action", string(c.action)), zap.String("reason", reason),
		zap.Bool("nas_acked", acked))
	return acked, nil
}
