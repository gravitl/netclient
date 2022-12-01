package wireguard

// NCIface.Create - makes a new Wireguard interface for darwin users (userspace)
func (nc *NCIface) Create() error {

	return nc.createUserSpaceWG()
}

// NCIface.ApplyAddrs - applies address for darwin userspace
func (nc *NCIface) ApplyAddrs() error {

	// cmd := exec.Command("ifconfig", getName(), "inet", nc.Settings.Address.IP.String(), nc.Settings.Address.IP.String())
	// if out, err := cmd.CombinedOutput(); err != nil {
	// 	logger.Log(0, fmt.Sprintf("adding addreess command \"%v\" failed with output %s and error: ", cmd.String(), out))
	// 	return err
	// }

	// if nc.Settings.NetworkRange.IP != nil {
	// 	cmd = exec.Command("route", "add", "-net", nc.Settings.NetworkRange.String(), "-interface", getName())
	// 	if out, err := cmd.CombinedOutput(); err != nil {
	// 		logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
	// 		return err
	// 	}
	// }

	// if nc.Settings.NetworkRange6.IP != nil {
	// 	cmd = exec.Command("route", "add", "-inet6", nc.Settings.NetworkRange.String(), "-interface", getName())
	// 	if out, err := cmd.CombinedOutput(); err != nil {
	// 		logger.Log(0, fmt.Sprintf("failed to add route with command %s - %v", cmd.String(), out))
	// 		return err
	// 	}
	// }

	// go func() {
	// 	time.Sleep(time.Minute)
	// }()

	return nil
}
