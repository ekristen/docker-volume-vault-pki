package main

import (
	"bytes"
	"crypto/md5"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/hashicorp/vault/api"
)

const (
	vaultpkiID    = "vaultpki"
	socketAddress = "/run/docker/plugins/vault-pki.sock"
)

var (
	defaultDir             = filepath.Join(volume.DefaultDockerRootDirectory, vaultpkiID)
	root                   = flag.String("root", defaultDir, "Vault PKI volumes root directory")
	ErrAddressNotSpecified = errors.New("address not specified")
	ErrNotImplemented      = errors.New("not yet implemented")
	ErrSecretDoesNotExist  = errors.New("secret does not exist")
)

type vaultpkiVolume struct {
	addr       string
	token      string
	path       string
	commonName string

	mountpoint  string
	connections int

	PkiSecret *api.Secret
}

type vaultpkiDriver struct {
	sync.RWMutex

	root    string
	volumes map[string]*vaultpkiVolume
}

func newVaultpkiDriver(root string) *vaultpkiDriver {
	d := &vaultpkiDriver{
		root:    root,
		volumes: make(map[string]*vaultpkiVolume),
	}

	return d
}

func (d *vaultpkiDriver) Create(r volume.Request) volume.Response {
	logrus.WithField("method", "create").Debugf("%#v", r)

	var volumeNameBuffer bytes.Buffer

	d.Lock()
	defer d.Unlock()

	v := &vaultpkiVolume{}
	if r.Options == nil || (r.Options["addr"] == "" && r.Options["token"] == "" && r.Options["path"] == "" && r.Options["common_name"] == "") {
		return responseError("addr, token, path and common_name options required")
	}

	volumeNameBuffer.WriteString(r.Options["path"])
	volumeNameBuffer.WriteString(r.Options["common_name"])

	v.addr = r.Options["addr"]
	v.token = r.Options["token"]
	v.path = r.Options["path"]
	v.commonName = r.Options["common_name"]
	v.mountpoint = filepath.Join(d.root, fmt.Sprintf("%x", md5.Sum([]byte(volumeNameBuffer.String()))))

	d.volumes[r.Name] = v
	return volume.Response{}
}

func (d *vaultpkiDriver) Remove(r volume.Request) volume.Response {
	logrus.WithField("method", "remove").Debugf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	if v.connections == 0 {
		if err := os.RemoveAll(v.mountpoint); err != nil {
			return responseError(err.Error())
		}
		delete(d.volumes, r.Name)
		return volume.Response{}
	}
	return responseError(fmt.Sprintf("volume %s is currently used by a container", r.Name))
}

func (d *vaultpkiDriver) Path(r volume.Request) volume.Response {
	logrus.WithField("method", "path").Debugf("%#v", r)

	d.RLock()
	defer d.RUnlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	return volume.Response{Mountpoint: v.mountpoint}
}

func (d *vaultpkiDriver) Mount(r volume.MountRequest) volume.Response {
	logrus.WithField("method", "mount").Debugf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	if v.connections > 0 {
		v.connections++
		return volume.Response{Mountpoint: v.mountpoint}
	}

	fi, err := os.Lstat(v.mountpoint)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(v.mountpoint, 0755); err != nil {
			return responseError(err.Error())
		}
	} else if err != nil {
		return responseError(err.Error())
	}

	if fi != nil && !fi.IsDir() {
		return responseError(fmt.Sprintf("%v already exist and it's not a directory", v.mountpoint))
	}

	if err := d.mountVolume(v); err != nil {
		return responseError(err.Error())
	}

	return volume.Response{Mountpoint: v.mountpoint}
}

func (d *vaultpkiDriver) Unmount(r volume.UnmountRequest) volume.Response {
	logrus.WithField("method", "unmount").Debugf("%#v", r)

	d.Lock()
	defer d.Unlock()
	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}
	if v.connections <= 1 {
		if err := d.unmountVolume(v.mountpoint); err != nil {
			return responseError(err.Error())
		}
		v.connections = 0
	} else {
		v.connections--
	}

	return volume.Response{}
}

func (d *vaultpkiDriver) Get(r volume.Request) volume.Response {
	logrus.WithField("method", "get").Debugf("%#v", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	return volume.Response{Volume: &volume.Volume{Name: r.Name, Mountpoint: v.mountpoint}}
}

func (d *vaultpkiDriver) List(r volume.Request) volume.Response {
	logrus.WithField("method", "list").Debugf("%#v", r)

	d.Lock()
	defer d.Unlock()

	var vols []*volume.Volume
	for name, v := range d.volumes {
		vols = append(vols, &volume.Volume{Name: name, Mountpoint: v.mountpoint})
	}
	return volume.Response{Volumes: vols}
}

func (d *vaultpkiDriver) Capabilities(r volume.Request) volume.Response {
	logrus.WithField("method", "capabilities").Debugf("%#v", r)

	return volume.Response{Capabilities: volume.Capability{Scope: "local"}}
}

func (d *vaultpkiDriver) mountVolume(v *vaultpkiVolume) error {
	defaultCfg := api.DefaultConfig()
	defaultCfg.Address = v.addr

	if v.addr == "" {
		return ErrAddressNotSpecified
	}

	vaultClient, err := api.NewClient(defaultCfg)
	if err != nil {
		return err
	}

	logrus.Debug("using token: %s", v.token)
	vaultClient.SetToken(v.token)

	data := map[string]interface{}{
		"common_name": v.commonName,
	}

	s, err := vaultClient.Logical().Write(v.path, data)
	if err != nil {
		return err
	}

	if s == nil {
		return ErrSecretDoesNotExist
	}

	v.PkiSecret = s

	// TODO: write out the files to the filesystem mountpoint????/????
	// TODO: write out all lease information?
	// TODO: write out all data entries in the JSON to the filesystem?

	// TODO: monitor lease expiration time, renew and update files at expiration / 2

	err = ioutil.WriteFile(strings.Join([]string{v.mountpoint, "certificate"}, "/"), []byte(s.Data["certificate"].(string)), 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(strings.Join([]string{v.mountpoint, "private_key"}, "/"), []byte(s.Data["private_key"].(string)), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (d *vaultpkiDriver) unmountVolume(target string) error {
	// remove directories??
	return nil
}

func responseError(err string) volume.Response {
	logrus.Error(err)
	return volume.Response{Err: err}
}

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	flag.Parse()

	d := newVaultpkiDriver(*root)
	h := volume.NewHandler(d)
	logrus.Infof("listening on %s", socketAddress)
	logrus.Error(h.ServeUnix("", socketAddress))
}
