package profiles

// ProfileStore defines the contract for security profile stores.
// Implemented by both the in-memory Store and db.ProfileStore.
type ProfileStore interface {
	List(pt ProfileType) []*Profile
	Get(id string) (*Profile, bool)
	Create(p *Profile, actor string) (*Profile, error)
	Update(id string, patch *Profile, actor string) (*Profile, error)
	Delete(id string) error
	Toggle(id string, enabled bool, actor string) (*Profile, error)
}
