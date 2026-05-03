package policy

// PolicyStore defines the contract for security policy stores.
// Implemented by both the in-memory Store and db.PolicyStore.
type PolicyStore interface {
	List() []SecurityPolicy
	Get(id string) (*SecurityPolicy, bool)
	Create(p *SecurityPolicy, author string) (int64, string)
	Update(p *SecurityPolicy, author string) (int64, bool, string)
	Delete(id, author string) (int64, bool, string)

	Lock(author string) (*ConfigLock, bool)
	Unlock(author string, force bool) bool
	GetLock() *ConfigLock

	Version() int64
	OnChange() <-chan int64

	ListVersions() []ConfigVersion
	GetVersion(version int64) (*ConfigVersion, bool)
	Revert(targetVersion int64, author string) (int64, bool)
	Diff(fromVersion, toVersion int64) map[string]string

	LoadDefaults()
}
