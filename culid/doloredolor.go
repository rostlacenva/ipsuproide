import (
	"context"
	"fmt"
	"io"

	healthcare "google.golang.org/api/healthcare/v1"
)

// approveFhirStoreIAMPolicy approves the IAM policy for the FHIR store.
func approveFhirStoreIAMPolicy(w io.Writer, projectID, location, datasetID, fhirStoreID string) error {
	ctx := context.Background()

	healthcareService, err := healthcare.NewService(ctx)
	if err != nil {
		return fmt.Errorf("healthcare.NewService: %v", err)
	}

	storesService := healthcareService.Projects.Locations.Datasets.FhirStores

	name := fmt.Sprintf("projects/%s/locations/%s/datasets/%s/fhirStores/%s", projectID, location, datasetID, fhirStoreID)

	policy, err := storesService.GetIamPolicy(name).Do()
	if err != nil {
		return fmt.Errorf("GetIamPolicy: %v", err)
	}

	policy.Bindings = append(policy.Bindings, &healthcare.Binding{
		Members: []string{"domain:google.com"},
		Role:    "roles/healthcare.fhirResourceReader",
	})

	req := &healthcare.SetIamPolicyRequest{Policy: policy}

	policy, err = storesService.SetIamPolicy(name, req).Do()
	if err != nil {
		return fmt.Errorf("SetIamPolicy: %v", err)
	}

	fmt.Fprintf(w, "IAM policy for FHIR store %q updated:\n", fhirStoreID)
	for _, b := range policy.Bindings {
		fmt.Fprintf(w, "%q: %q\n", b.Role, b.Members)
	}

	return nil
}
  
