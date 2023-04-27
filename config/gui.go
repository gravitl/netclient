package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const GUILockFile = "gui.lock"

var gui Gui

type Gui struct {
	Address string
	Port    string
}

// SetGUI - set GUI configuration
func SetGUI(a, p string) {
	gui.Address = a
	gui.Port = p
}

// GetGUI - get GUI configuration
func GetGUI() *Gui {
	return &gui
}

// WriteGUIConfiig writes the in memory gui configuration to disk
func WriteGUIConfig() error {
	lockfile := filepath.Join(os.TempDir(), GUILockFile)
	file := GetNetclientPath() + "gui.yml"
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(GetNetclientPath(), os.ModePerm)
		} else if err != nil {
			return err
		}
	}
	if Lock(lockfile) != nil {
		return errors.New("failed to obtain lockfile")
	}
	defer Unlock(lockfile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	err = yaml.NewEncoder(f).Encode(gui)
	if err != nil {
		return err
	}
	return f.Sync()
}

// ReadGUIConfig reads the host configuration file and returns it as an instance.
func ReadGUIConfig() (*Gui, error) {
	lockfile := filepath.Join(os.TempDir(), GUILockFile)
	file := GetNetclientPath() + "gui.yml"
	if err := Lock(lockfile); err != nil {
		return nil, err
	}
	defer Unlock(lockfile)
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&gui); err != nil {
		return nil, err
	}
	return &gui, nil
}
