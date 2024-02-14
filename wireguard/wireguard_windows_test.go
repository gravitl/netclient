package wireguard

import "testing"

// TestGetDefaultGatewayIpFromRouteList
func TestGetDefaultGatewayIpFromRouteList(t *testing.T) {
	//Case1
	s1 := `Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name
	-------  --------  ---  ------------------------  ---  ------------------------
	No       Manual    26   0.0.0.0/0                   3  192.168.1.1
	No       System    256  10.100.10.0/24             10  netmaker
	No       System    256  10.100.10.5/32             10  netmaker
	No       System    256  10.100.10.255/32           10  netmaker
	No       Manual    1    24.199.68.179/32            3  192.168.1.1
	No       Manual    1    64.233.164.127/32           3  192.168.1.1`

	ip := getDefaultGatewayIpFromRouteList(s1)
	if ip != "192.168.1.1" {
		t.Errorf("Expect 192.168.1.1 returned, but got: %s", ip)
	}

	//Case2
	s1 = `Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name
		-------  --------  ---  ------------------------  ---  ------------------------
		No       Manual    26   0.0.0.0/0                   3  192.168.1.2
		No       System    256  10.100.10.0/24             10  netmaker
		No       System    256  10.100.10.5/32             10  netmaker
		No       System    256  10.100.10.255/32           10  netmaker
		No       Manual    1    24.199.68.179/32            3  192.168.1.1
		No       Manual    1    64.233.164.127/32           3  192.168.1.1`

	ip = getDefaultGatewayIpFromRouteList(s1)
	if ip != "192.168.1.2" {
		t.Errorf("Expect 192.168.1.2 returned, but got: %s", ip)
	}

}
