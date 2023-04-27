package daemon

import (
	"errors"
	"log"
	"os"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
)

const ExecDir = "/sbin/"

// install -- sets up daemon for freebsd
func install() error {
	binarypath, err := os.Executable()
	if err != nil {
		return err
	}
	_, err = os.Stat("/etc/netclient")
	if os.IsNotExist(err) {
		if err := os.MkdirAll("/etc/netclient", 0775); err != nil {
			return err
		}
		if err := os.Chmod(GetNetclientPath(), 0x775); err != nil {
			logger.Log(0, "error updating permissions for /etc/netclient", err.Error())
		}
	} else if err != nil {
		log.Println("couldnt find or create /etc/netclient")
		return err
	}
	//install binary
	if ncutils.FileExists(ExecDir + "netclient") {
		logger.Log(0, "updating netclient binary in ", ExecDir)
	}
	err = ncutils.Copy(binarypath, ExecDir+"netclient")
	if err != nil {
		logger.Log(0, err.Error())
		return err
	}

	rcFile := `#!/bin/sh
#
# PROVIDE: netclient
# REQUIRE: LOGIN
# KEYWORD: shutdown

# Description:
#    This script runs netclient as a service as root on boot

# How to use:
#    Place this file in /usr/local/etc/rc.d/
#    Add netclient="YES" to /etc/rc.config.d/netclient
#    To pass args, add netclient_args="daemon" to /etc/rc.config.d/netclient

# Freebsd rc library
. /etc/rc.subr

# General Info
name="netclient"            # Safe name of program
program_name="netclient"   # Name of exec
title="netclient"          # Title to display in top/htop

# RC.config vars
load_rc_config $name      # Loading rc config vars
: ${netclient_enable="YES"}  # Default: enable netclient
: ${netclient_runAs="root"} # Default: Run Node-RED as root

# Freebsd Setup
rcvar=netclient_enable                   # Enables the rc.conf YES/NO flag

# Env Setup
#export HOME=$( getent passwd "$netclient_runAs" | cut -d: -f6 ) # Gets the home directory of the runAs user

# Command Setup
exec_path="/sbin/${program_name}" # Path to the netclient exec
output_file="/var/log/${program_name}.log" # Path to netclient logs

# Command
command="/usr/sbin/daemon"
command_args="-r -t ${title} -u ${netclient_runAs} -o ${output_file} ${exec_path} ${netclient_args}"

# Loading Config
load_rc_config ${name}
run_rc_command "$1"
`

	rcConfig := `netclient="YES"
netclient_args="daemon"`

	rcbytes := []byte(rcFile)
	if !ncutils.FileExists("/etc/rc.d/netclient") {
		err := os.WriteFile("/etc/rc.d/netclient", rcbytes, 0744)
		if err != nil {
			return err
		}
		rcConfigbytes := []byte(rcConfig)
		if !ncutils.FileExists("/etc/rc.conf.d/netclient") {
			err := os.WriteFile("/etc/rc.conf.d/netclient", rcConfigbytes, 0644)
			if err != nil {
				return err
			}
			start()
			return nil
		}
	}
	return nil
}

func start() error {
	return service("start")
}

func stop() error {
	return service("stop")
}

// service- accepts args to service netclient and applies
func service(command string) error {
	if _, err := ncutils.RunCmdFormatted("service netclient "+command, true); err != nil {
		return err
	}
	return nil
}

// cleanUp- removes config files and netclient binary
func cleanUp() error {
	var faults bool
	if _, err := ncutils.RunCmd("service netclient stop", false); err != nil {
		faults = true
	}
	if err := removeFreebsdDaemon(); err != nil {
		faults = true
	}
	if err := os.RemoveAll(config.GetNetclientPath()); err != nil {
		logger.Log(1, "Removing netclient configs: ", err.Error())
		faults = true
	}
	if err := os.Remove(ExecDir + "netclient"); err != nil {
		logger.Log(1, "Removing netclient binary: ", err.Error())
		faults = true
	}
	if err := os.Remove("/var/log/netclient.log"); err != nil {
		logger.Log(1, "error removing netclient log file", err.Error())
		faults = true
	}
	if faults {
		return errors.New("error removing removing netclient files and configs")
	}
	return nil
}

// removeFreebsdDaemon - remove freebsd daemon
func removeFreebsdDaemon() error {
	var faults bool
	if ncutils.FileExists("/etc/rc.d/netclient") {
		err := os.Remove("/etc/rc.d/netclient")
		if err != nil {
			logger.Log(0, "Error removing /etc/rc.d/netclient. Please investigate.")
			faults = true
		}
	}
	if ncutils.FileExists("/etc/rc.conf.d/netclient") {
		err := os.Remove("/etc/rc.conf.d/netclient")
		if err != nil {
			faults = true
			logger.Log(0, "Error removing /etc/rc.conf.d/netclient. Please investigate.")
		}
	}
	if faults {
		return errors.New("error removing daemon")
	}
	return nil
}
