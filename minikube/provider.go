package minikube

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

type ProviderConfig struct {
	Profile string
}

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"profile": {
				Type:        schema.TypeString,
				Description: "The name of the minikube VM being used. This can be modified to allow for multiple minikube instances to be run independently (default \"minikube\")",
				Default:     "minikube",
				ForceNew:    true,
				Optional:    true,
			},
		},
		DataSourcesMap: map[string]*schema.Resource{},
		ResourcesMap: map[string]*schema.Resource{
			"minikube": Minikube(),
		},

		ConfigureFunc: func(d *schema.ResourceData) (interface{}, error) {
			return ProviderConfig{
				Profile: d.Get("profile").(string),
			}, nil
		},
	}
}
