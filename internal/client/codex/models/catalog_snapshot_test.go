package models

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// This smoke check also runs after CI refreshes catalogs. It derives model IDs
// from the catalog being built, while the full suite tests the committed snapshot.
func TestCurrentCatalogBuildsModelResponse(t *testing.T) {
	raw, revision := registry.GetCodexClientModelsSnapshot()
	if revision == 0 {
		t.Fatal("missing current catalog")
	}
	var catalog struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Models) == 0 {
		t.Fatal("empty current catalog")
	}
	available := []map[string]any{{"id": "catalog-smoke-custom"}}
	for _, model := range catalog.Models {
		available = append(available, map[string]any{"id": model["slug"]})
	}
	response := BuildResponse(available, nil, false)
	models, ok := response["models"].([]map[string]any)
	if !ok || len(models) != len(available) {
		t.Fatalf("built %d models, want %d", len(models), len(available))
	}
	seen := make(map[string]bool)
	for _, model := range models {
		id, _ := model["slug"].(string)
		if id == "" || seen[id] || model["base_instructions"] == "" || model["base_instructions"] == nil {
			t.Fatalf("unusable model entry: %q", id)
		}
		seen[id] = true
	}
	for _, model := range available {
		if !seen[model["id"].(string)] {
			t.Fatalf("missing model %s", model["id"])
		}
	}
	if _, err := MarshalCompact(response); err != nil {
		t.Fatal(err)
	}
}
