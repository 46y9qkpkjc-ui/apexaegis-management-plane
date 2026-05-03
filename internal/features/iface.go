package features

// FeatureStore defines the contract for feature licensing stores.
// Implemented by both the in-memory Store and db.FeatureStore.
type FeatureStore interface {
	List() []*Feature
	Get(id string) (*Feature, bool)
	Toggle(id string, enabled bool, orgPlan string, actor string) (*Feature, error)
	StartTrial(id string, actor string) (*Feature, error)
	IsEnabled(id string) bool
}
