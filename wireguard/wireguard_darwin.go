package wireguard

// NCIface.Create - makes a new Wireguard interface for darwin users (userspace)
func (nc *NCIface) Create() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	return nc.createUserSpaceWG()
}

func (nc *NCIface) assignAddr() error {

	cmd := exec.Command("ifconfig", nc.Settings.Interface, "inet", nc.Settings.Address.IP.String(), nc.Settings.Address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("adding addreess command \"%v\" failed with output %s and error: ", cmd.String(), out)
		return err
	}

	cmd = exec.Command("route", "add", "-net", nc.Settings.Address.Network.String(), "-interface", w.Name)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		logger.log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
		return err
	}

	return nil
}
