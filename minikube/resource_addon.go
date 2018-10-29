package minikube

import (
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/spf13/viper"
	"k8s.io/minikube/cmd/minikube/cmd/config"
	pkgConfig "k8s.io/minikube/pkg/minikube/config"
)

const (
	addonKey = "addon"
)

func Addon() *schema.Resource {
	return &schema.Resource{
		Create: enableAddon,
		Delete: disableAddon,
		Read:   readAddon,

		Schema: map[string]*schema.Schema{
			"addon": {
				Type:        schema.TypeString,
				Description: "The addon to be enabled",
				ForceNew:    true,
				Optional:    false,
			},
		},
	}
}

func enableAddon(d *schema.ResourceData, meta interface{}) error {
	providerConfig := meta.(*ProviderConfig)
	viper.Set(pkgConfig.MachineProfile, providerConfig.Profile)

	addon := d.Get(addonKey).(string)

	err := config.Set(addon, "true")
	if err != nil {
		log.Println("Unable to enable addon: ", err)
	}

	return nil
}

func readAddon(d *schema.ResourceData, meta interface{}) error {
	providerConfig := meta.(*ProviderConfig)
	viper.Set(pkgConfig.MachineProfile, providerConfig.Profile)

	addon := d.Get(addonKey).(string)

	val, err := pkgConfig.Get(addon)
	if err != nil {
		log.Println("Unable to verify addon status: ", err)
		return err
	}

	log.Printf("Addon %s enabled: %s\n", addon, val)

	return nil
}

func disableAddon(d *schema.ResourceData, meta interface{}) error {
	providerConfig := meta.(*ProviderConfig)
	viper.Set(pkgConfig.MachineProfile, providerConfig.Profile)

	addon := d.Get(addonKey).(string)

	err := config.Set(addon, "false")
	if err != nil {
		log.Println("Unable to disable addon: ", err)
	}

	return nil
}
