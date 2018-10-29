package minikube

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"encoding/base64"

	"github.com/blang/semver"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/docker/machine/libmachine/state"
	"k8s.io/minikube/cmd/minikube/cmd"
	"k8s.io/minikube/pkg/minikube/cluster"
	cmdUtil "k8s.io/minikube/cmd/util"
	"k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/minikube/constants"
	"k8s.io/minikube/pkg/minikube/machine"
	pkgutil "k8s.io/minikube/pkg/util"
	"k8s.io/minikube/pkg/util/kubeconfig"
	"k8s.io/minikube/pkg/version"
	"github.com/spf13/viper"
)

var (
	clusterBootstrapper string = "kubeadm"
)

func Minikube() *schema.Resource {
	return &schema.Resource{
		Create: resourceMinikubeCreate,
		Read:   resourceMinikubeRead,
		Delete: resourceMinikubeDelete,

		Schema: map[string]*schema.Schema{
			"apiserver_name": {
				Type:        schema.TypeString,
				Description: "The apiserver name which is used in the generated certificate for localkube/kubernetes.  This can be used if you want to make the apiserver available from outside the machine (default \"minikubeCA\")",
				Default:     "minikubeCA",
				ForceNew:    true,
				Optional:    true,
			},
			"cache_images": {
				Type:        schema.TypeBool,
				Description: "If true, cache docker images for the current bootstrapper and load them into the machine. (default true)",
				Default:     true,
				ForceNew:    true,
				Optional:    true,
			},
			"container_runtime": {
				Type:        schema.TypeString,
				Description: "The container runtime to be used",
				Default:     "docker",
				ForceNew:    true,
				Optional:    true,
			},
			"cpus": {
				Type:        schema.TypeInt,
				Description: "Number of CPUs allocated to the minikube VM (default 2)",
				Default:     2,
				ForceNew:    true,
				Optional:    true,
			},
			"disable_driver_mounts": {
				Type:        schema.TypeBool,
				Description: "Disables the filesystem mounts provided by the hypervisors (vboxfs, xhyve-9p)",
				Default:     true,
				ForceNew:    true,
				Optional:    true,
			},
			"disk_size": {
				Type:        schema.TypeString,
				Description: "Disk size allocated to the minikube VM (format: <number>[<unit>], where unit = b, k, m or g) (default \"20g\")",
				Default:     "20g",
				ForceNew:    true,
				Optional:    true,
			},
			"dns_domain": {
				Type:        schema.TypeString,
				Description: "The cluster dns domain name used in the kubernetes cluster (default \"cluster.local\")",
				Default:     "cluster.local",
				ForceNew:    true,
				Optional:    true,
			},
			"docker_env": {
				Type:        schema.TypeList,
				Description: "Environment variables to pass to the Docker daemon. (format: key=value)",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
			},
			"docker_opt": {
				Type:        schema.TypeList,
				Description: "Specify arbitrary flags to pass to the Docker daemon. (format: key=value)",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
			},
			"extra_config": {
				Type: schema.TypeString,
				Description: "A set of key=value pairs that describe configuration that may be passed to different components.\nThe key should be '.' separated, and the first part before the dot is the component to apply the configuration to.\nValid components are: kubelet, apiserver, controller-manager, etcd, proxy, scheduler.",
				Default:  "",
				ForceNew: true,
				Optional: true,
			},
			"feature_gates": {
				Type:        schema.TypeString,
				Description: "A set of key=value pairs that describe feature gates for alpha/experimental features.",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"host_only_cidr": {
				Type:        schema.TypeString,
				Description: "The CIDR to be used for the minikube VM (only supported with Virtualbox driver) (default \"192.168.99.1/24\")",
				Default:     "192.168.99.1/24",
				ForceNew:    true,
				Optional:    true,
			},
			"hyperv_virtual_switch": {
				Type:        schema.TypeString,
				Description: "The hyperv virtual switch name. Defaults to first found. (only supported with HyperV driver)",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"insecure_registry": {
				Type:        schema.TypeList,
				Description: "Insecure Docker registries to pass to the Docker daemon (default [10.0.0.0/24])",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew: true,
				Optional: true,
			},
			"iso_url": {
				Type:        schema.TypeString,
				Description: "Location of the minikube iso (default \"https://storage.googleapis.com/minikube/iso/minikube-v0.30.0.iso\")",
				Default:     "https://storage.googleapis.com/minikube/iso/minikube-v0.30.0.iso",
				ForceNew:    true,
				Optional:    true,
			},
			"keep_context": {
				Type:        schema.TypeBool,
				Description: "This will keep the existing kubectl context and will create a minikube context.",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"kubernetes_version": {
				Type: schema.TypeString,
				Description: "The kubernetes version that the minikube VM will use (ex: v1.2.3)\nOR a URI which contains a localkube binary (ex: https://storage.googleapis.com/minikube/k8sReleases/v1.3.0/localkube-linux-amd64) (default \"v1.10.0\")",
				Default:  "v1.10.0",
				ForceNew: true,
				Optional: true,
			},
			"kvm_network": {
				Type:        schema.TypeString,
				Description: "The KVM network name. (only supported with KVM driver) (default \"default\")",
				Default:     "default",
				ForceNew:    true,
				Optional:    true,
			},
			"memory": {
				Type:        schema.TypeInt,
				Description: "Amount of RAM allocated to the minikube VM (default 2048)",
				Default:     2048,
				ForceNew:    true,
				Optional:    true,
			},
			"mount": {
				Type:        schema.TypeBool,
				Description: "This will start the mount daemon and automatically mount files into minikube",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"mount_string": {
				Type:        schema.TypeString,
				Description: "The argument to pass the minikube mount command on start (default \"/Users:/minikube-host\")",
				Default:     "/Users:/minikube-host",
				ForceNew:    true,
				Optional:    true,
			},
			"network_plugin": {
				Type:        schema.TypeString,
				Description: "The name of the network plugin",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"registry_mirror": {
				Type:        schema.TypeList,
				Description: "Registry mirrors to pass to the Docker daemon",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
			},
			"vm_driver": {
				Type:        schema.TypeString,
				Description: "VM driver is one of: [virtualbox xhyve vmwarefusion] (default \"virtualbox\")",
				Default:     "virtualbox",
				ForceNew:    true,
				Optional:    true,
			},
			"xhyve_disk_driver": {
				Type:        schema.TypeString,
				Description: "The disk driver to use [ahci-hd|virtio-blk] (only supported with xhyve driver) (default \"ahci-hd\")",
				Default:     "ahci-hd",
				ForceNew:    true,
				Optional:    true,
			},
			"client_certificate": {
				Type:        schema.TypeString,
				Description: "Base64 encoded public certificate used by clients to authenticate to the cluster endpoint.",
				Computed:    true,
			},
			"client_key": {
				Type:        schema.TypeString,
				Description: "Base64 encoded private key used by clients to authenticate to the cluster endpoint.",
				Computed:    true,
			},
			"cluster_ca_certificate": {
				Type:        schema.TypeString,
				Description: "Base64 encoded public certificate that is the root of trust for the cluster.",
				Computed:    true,
			},
			"endpoint": {
				Type:        schema.TypeString,
				Description: "Endpoint that can be used to reach API server",
				Computed:    true,
			},
		},
	}
}

func resourceMinikubeRead(d *schema.ResourceData, meta interface{}) error {
	providerConfig := meta.(ProviderConfig)
	viper.Set(config.MachineProfile, providerConfig.Profile)

	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	ms, err := cluster.GetHostStatus(api)
	if err != nil {
		log.Printf("Error getting machine status: %v", err)
		return err
	}

	cs := state.None.String()
	ks := state.None.String()
	if ms == state.Running.String() {
		clusterBootstrapper, err := cmd.GetClusterBootstrapper(api, clusterBootstrapper)
		if err != nil {
			log.Printf("Error getting cluster bootstrapper: %s", err)
			return err
		}
		cs, err = clusterBootstrapper.GetClusterStatus()
		if err != nil {
			log.Printf("Error cluster status: %v", err)
			return err
		}

		ip, err := cluster.GetHostDriverIP(api)
		if err != nil {
			log.Printf("Error host driver ip status: %v", err)
			return err
		}
		kstatus, err := kubeconfig.GetKubeConfigStatus(ip, cmdUtil.GetKubeConfigPath(), config.GetMachineName())
		if err != nil {
			log.Printf("Error kubeconfig status: %v", err)
			return err
		}
		if kstatus {
			ks = "Correctly Configured: pointing to minikube-vm at " + ip.String()
		} else {
			ks = "Misconfigured: pointing to stale minikube-vm.\nTo fix the kubectl context, run minikube update-context"
		}
	}

	status := cmd.Status{
		MinikubeStatus: ms, 
		ClusterStatus: cs,
		KubeconfigStatus: ks,
	}
	log.Printf("Result: %v", status)

	return nil
}

func resourceMinikubeCreate(d *schema.ResourceData, meta interface{}) error {
	providerConfig := meta.(ProviderConfig)
	viper.Set(config.MachineProfile, providerConfig.Profile)
	
	machineConfig, err := getMachineConfig(d)
	if err != nil {
		return err
	}

	kubernetesConfig := getKubernetesConfig(providerConfig, d)

	log.Println("=================== Creating Minikube Cluster ==================")

	if kubernetesConfig.ShouldLoadCachedImages {
		go machine.CacheImagesForBootstrapper(kubernetesConfig.KubernetesVersion, clusterBootstrapper)
	}

	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	exists, err := api.Exists(providerConfig.Profile)
	if err != nil {
		log.Printf("checking if machine exists: %s", err)
		return err
	}

	host := NewHost(machineConfig, api)
	err = host.Start()
	if err != nil {
		log.Printf("Error starting host: %v", err)
		return err
	}

	kubernetesConfig.NodeIP, err = host.GetIP()
	if err != nil {
		log.Printf("Error getting VM IP address: %v", err)
		return err
	}

	// Write profile cluster configuration to file
	clusterConfig := config.Config{
		MachineConfig:    machineConfig,
		KubernetesConfig: kubernetesConfig,
	}

	if err := saveConfig(providerConfig, clusterConfig); err != nil {
		log.Printf("Error saving profile cluster configuration: %v", err)
	}

	// Kubernetes

	k8sBootstrapper, err := cmd.GetClusterBootstrapper(api, clusterBootstrapper)
	if err != nil {
		log.Printf("Error getting cluster bootstrapper: %s", err)
		return err
	}

	log.Println("Moving files into cluster...")
	if err := k8sBootstrapper.UpdateCluster(kubernetesConfig); err != nil {
		log.Printf("Error updating cluster: %v", err)
		return err
	}

	log.Println("Setting up certs...")
	if err := k8sBootstrapper.SetupCerts(kubernetesConfig); err != nil {
		log.Printf("Error configuring authentication: %v", err)
		return err
	}

	log.Println("Connecting to cluster...")
	kubeHost, err := host.GetURL()
	if err != nil {
		log.Printf("Error connecting to cluster: %v", err)
	}

	log.Println("Setting up kubeconfig...")
	kubeConfigFile := cmdUtil.GetKubeConfigPath()
	kubeCfgSetup := &kubeconfig.KubeConfigSetup{
		ClusterName:          config.GetMachineName(),
		ClusterServerAddress: kubeHost,
		ClientCertificate:    constants.MakeMiniPath("client.crt"),
		ClientKey:            constants.MakeMiniPath("client.key"),
		CertificateAuthority: constants.MakeMiniPath("ca.crt"),
		KeepContext:          d.Get("keep_context").(bool),
	}
	kubeCfgSetup.SetKubeConfigFile(kubeConfigFile)

	if err := kubeconfig.SetupKubeConfig(kubeCfgSetup); err != nil {
		log.Printf("Error setting up kubeconfig: %v", err)
		return err
	}

	log.Println("Starting cluster components...")

	if !exists {
		log.Println("Starting k8s...")
		if err := k8sBootstrapper.StartCluster(kubernetesConfig); err != nil {
			log.Printf("Error starting cluster: %v", err)
			return err
		}
	} else {
		log.Println("Restarting k8s...")
		if err := k8sBootstrapper.RestartCluster(kubernetesConfig); err != nil {
			log.Printf("Error restarting cluster: %v", err)
			return err
		}
	}

	if d.Get("mount").(bool) {
		mountString := d.Get("mount_string").(string)
		log.Printf("Setting up hostmount on %s...\n", mountString)

		path := os.Args[0]
		mountDebugVal := 0
		mountCmd := exec.Command(path, "mount", fmt.Sprintf("--v=%d", mountDebugVal), mountString)
		mountCmd.Env = append(os.Environ(), constants.IsMinikubeChildProcess+"=true")
		err = mountCmd.Start()
		if err != nil {
			log.Printf("Error running command minikube mount %s", err)
			return err
		}
		err = ioutil.WriteFile(filepath.Join(constants.GetMinipath(), constants.MountProcessFileName), []byte(strconv.Itoa(mountCmd.Process.Pid)), 0644)
		if err != nil {
			log.Printf("Error writing mount process pid to file: %s", err)
			return err
		}
	}

	if kubeCfgSetup.KeepContext {
		log.Printf("The local Kubernetes cluster has started. The kubectl context has not been altered, kubectl will require \"--context=%s\" to use the local Kubernetes cluster.\n",
			kubeCfgSetup.ClusterName)
	} else {
		log.Println("Kubectl is now configured to use the cluster.")
	}

	if machineConfig.VMDriver == "none" {
		log.Println(`===================
WARNING: IT IS RECOMMENDED NOT TO RUN THE NONE DRIVER ON PERSONAL WORKSTATIONS
	The 'none' driver will run an insecure kubernetes apiserver as root that may leave the host vulnerable to CSRF attacks
`)

		if os.Getenv("CHANGE_MINIKUBE_NONE_USER") == "" {
			log.Println(`When using the none driver, the kubectl config and credentials generated will be root owned and will appear in the root home directory.
You will need to move the files to the appropriate location and then set the correct permissions.  An example of this is below:

	sudo mv /root/.kube $HOME/.kube # this will write over any previous configuration
	sudo chown -R $USER $HOME/.kube
	sudo chgrp -R $USER $HOME/.kube

	sudo mv /root/.minikube $HOME/.minikube # this will write over any previous configuration
	sudo chown -R $USER $HOME/.minikube
	sudo chgrp -R $USER $HOME/.minikube

This can also be done automatically by setting the env var CHANGE_MINIKUBE_NONE_USER=true`)
		}
		if err := pkgutil.MaybeChownDirRecursiveToMinikubeUser(constants.GetMinipath()); err != nil {
			log.Printf("Error recursively changing ownership of directory %s: %s",
				constants.GetMinipath(), err)
			return err
		}
	}

	log.Println("Loading cached images from config file.")
	err = cmd.LoadCachedImagesInConfigFile()
	if err != nil {
		log.Println("Unable to load cached images from config file.")
	}

	d.SetId(providerConfig.Profile)

	client_certificate, err := readFileAsBase64String(kubeCfgSetup.ClientCertificate)
	if err != nil {
		log.Printf("Failed to read client_certificate (%s)", kubeCfgSetup.ClientCertificate)
		return err
	}
	client_key, err := readFileAsBase64String(kubeCfgSetup.ClientKey)
	if err != nil {
		log.Printf("Failed to read client_key (%s)", kubeCfgSetup.ClientKey)
		return err
	}
	cluster_ca_certificate, err := readFileAsBase64String(kubeCfgSetup.CertificateAuthority)
	if err != nil {
		log.Printf("Failed to read cluster_ca_certificate (%s)", kubeCfgSetup.CertificateAuthority)
		return err
	}

	d.Set("client_certificate", client_certificate)
	d.Set("client_key", client_key)
	d.Set("cluster_ca_certificate", cluster_ca_certificate)
	d.Set("endpoint", kubeHost)
	return err
}

func resourceMinikubeDelete(d *schema.ResourceData, meta interface{}) error {
	providerConfig := meta.(ProviderConfig)
	viper.Set(config.MachineProfile, providerConfig.Profile)
	
	log.Println("Deleting local Kubernetes cluster...")
	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	if err = cluster.DeleteHost(api); err != nil {
		log.Println("Errors occurred deleting machine: ", err)
		return err
	}
	log.Println("Machine deleted.")

	if err := cmdUtil.KillMountProcess(); err != nil {
		log.Println("Errors occurred deleting mount process: ", err)
	}

	if err := os.Remove(constants.GetProfileFile(providerConfig.Profile)); err != nil {
		log.Println("Error deleting machine profile config")
		return err
	}
	d.SetId("")
	return nil
}

func loadConfigFromFile(profile string) (config.Config, error) {
	var cc config.Config

	profileConfigFile := constants.GetProfileFile(profile)

	if _, err := os.Stat(profileConfigFile); os.IsNotExist(err) {
		return cc, err
	}

	data, err := ioutil.ReadFile(profileConfigFile)
	if err != nil {
		return cc, err
	}

	if err := json.Unmarshal(data, &cc); err != nil {
		return cc, err
	}
	return cc, nil
}

// saveConfig saves profile cluster configuration in
// $MINIKUBE_HOME/profiles/<profilename>/config.json
func saveConfig(providerConfig ProviderConfig, clusterConfig config.Config) error {
	data, err := json.MarshalIndent(clusterConfig, "", "    ")
	if err != nil {
		return err
	}

	profileConfigFile := constants.GetProfileFile(providerConfig.Profile)

	if err := os.MkdirAll(filepath.Dir(profileConfigFile), 0700); err != nil {
		return err
	}

	if err := saveConfigToFile(data, profileConfigFile); err != nil {
		return err
	}

	return nil
}

func saveConfigToFile(data []byte, file string) error {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return ioutil.WriteFile(file, data, 0600)
	}

	tmpfi, err := ioutil.TempFile(filepath.Dir(file), "config.json.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfi.Name())

	if err = ioutil.WriteFile(tmpfi.Name(), data, 0600); err != nil {
		return err
	}

	if err = tmpfi.Close(); err != nil {
		return err
	}

	if err = os.Remove(file); err != nil {
		return err
	}

	if err = os.Rename(tmpfi.Name(), file); err != nil {
		return err
	}
	return nil
}

func getMachineConfig(d *schema.ResourceData) (config.MachineConfig, error) {
	dockerEnv, ok := d.GetOk("docker_env"); if ! ok {
		dockerEnv = []string{}
	}
	dockerOpt, ok := d.GetOk("docker_opt"); if ! ok {
		dockerOpt = []string{}
	}
	insecureRegistry, ok := d.GetOk("insecure_registry"); if ! ok {
		insecureRegistry = []string{"10.0.0.0/24"}
	}
	registryMirror, ok := d.GetOk("registry_mirror"); if ! ok {
		registryMirror = []string{}
	}
	
	diskSize, err := getDiskSize(d)
	if err != nil {
		log.Printf("Error parsing disk size: %v", err)
		return config.MachineConfig{}, err
	}

	return config.MachineConfig{
		MinikubeISO:         d.Get("iso_url").(string),
		Memory:              d.Get("memory").(int),
		CPUs:                d.Get("cpus").(int),
		DiskSize:            diskSize,
		VMDriver:            d.Get("vm_driver").(string),
		XhyveDiskDriver:     d.Get("xhyve_disk_driver").(string),
		DockerEnv:           dockerEnv.([]string),
		DockerOpt:           dockerOpt.([]string),
		InsecureRegistry:    insecureRegistry.([]string),
		RegistryMirror:      registryMirror.([]string),
		HostOnlyCIDR:        d.Get("host_only_cidr").(string),
		HypervVirtualSwitch: d.Get("hyperv_virtual_switch").(string),
		KvmNetwork:          d.Get("kvm_network").(string),
		Downloader:          pkgutil.DefaultDownloader{},
		DisableDriverMounts: d.Get("disable_driver_mounts").(bool),
	}, nil
}

func getKubernetesConfig(providerConfig ProviderConfig, d *schema.ResourceData) config.KubernetesConfig {
	kubernetesConfig := config.KubernetesConfig{
		KubernetesVersion:      d.Get("kubernetes_version").(string),
		NodeName:               constants.DefaultNodeName,
		APIServerName:          d.Get("apiserver_name").(string),
		DNSDomain:              d.Get("dns_domain").(string),
		FeatureGates:           d.Get("feature_gates").(string),
		ContainerRuntime:       d.Get("container_runtime").(string),
		NetworkPlugin:          d.Get("network_plugin").(string),
		ServiceCIDR:            pkgutil.DefaultServiceCIDR,
		ShouldLoadCachedImages: d.Get("cache_images").(bool),
	}

	// Load profile cluster config from file
	cc, err := loadConfigFromFile(providerConfig.Profile)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Error loading profile config: %v", err)
	}
	if err == nil {
		oldKubernetesVersion, err := semver.Make(strings.TrimPrefix(cc.KubernetesConfig.KubernetesVersion, version.VersionPrefix))
		if err != nil {
			log.Printf("Error parsing version semver: %v", err)
		}

		newKubernetesVersion, err := semver.Make(strings.TrimPrefix(kubernetesConfig.KubernetesVersion, version.VersionPrefix))
		if err != nil {
			log.Printf("Error parsing version semver: %v", err)
		}

		// Check if it's an attempt to downgrade version. Avoid version downgrad.
		if newKubernetesVersion.LT(oldKubernetesVersion) {
			kubernetesConfig.KubernetesVersion = version.VersionPrefix + oldKubernetesVersion.String()
			log.Println("Kubernetes version downgrade is not supported. Using version:", kubernetesConfig.KubernetesVersion)
		}
	}

	return kubernetesConfig
}

func getDiskSize(d *schema.ResourceData) (int, error) {
	diskSize := d.Get("disk_size").(string)
	diskSizeMB := pkgutil.CalculateDiskSizeInMB(diskSize)
	if diskSizeMB < constants.MinimumDiskSizeMB {
		return 0, fmt.Errorf("Disk Size %dMB (%s) is too small, the minimum disk size is %dMB", diskSizeMB, diskSize, constants.MinimumDiskSizeMB)
	}

	return diskSizeMB, nil
}

func readFileAsBase64String(path string) (string, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(file), nil
}
