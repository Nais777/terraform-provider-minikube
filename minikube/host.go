package minikube

import (
	"strconv"
	"strings"

	"github.com/docker/machine/libmachine"
	"github.com/docker/machine/libmachine/host"
	"k8s.io/minikube/pkg/minikube/cluster"
	"k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/util"
)

type Host struct {
	config     config.MachineConfig
	api libmachine.API
	vmInstance *host.Host
}

func NewHost(config config.MachineConfig, api libmachine.API) Host {
	return Host{
		config: config,
		api: api,
	}
}

func (h *Host) Start() error {
	host, err := cluster.StartHost(h.api, h.config)
	if err != nil {
		return err
	}

	h.vmInstance = host

	return nil
}

func (h *Host) GetIP() (string, error) {
	ip, err := h.vmInstance.Driver.GetIP()
	if err != nil {
		return "", err
	}

	return ip, nil
}

func (h *Host) GetURL() (string, error)  {
	kubeHost, err := h.vmInstance.Driver.GetURL()
	if err != nil {
		return "", err
	}
	kubeHost = strings.Replace(kubeHost, "tcp://", "https://", -1)
	kubeHost = strings.Replace(kubeHost, ":2376", ":"+strconv.Itoa(util.APIServerPort), -1)

	return kubeHost, nil
}
