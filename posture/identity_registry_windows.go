package posture

import (
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

const (
	cloudDomainJoinPath = `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`
	workplaceJoinRel    = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo`
	biosRegPath         = `HARDWARE\DESCRIPTION\System\BIOS`
)

// readLocalMachineStringValue reads a REG_SZ value from HKLM. This works from
// the netclient Windows service (SYSTEM) where PowerShell/CIM often fails.
func readLocalMachineStringValue(keyPath, valueName string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// readJoinInfoFromRegistry collects Entra / workplace identifiers from registry
// hives that remain visible to SYSTEM. dsregcmd only surfaces workplace-join
// state for the interactive user, so registry is required for services.
func readJoinInfoFromRegistry() (deviceID, userEmail string) {
	deviceID, userEmail = readCloudDomainJoin()
	wpID, wpEmail := readWorkplaceJoin()
	if deviceID == "" {
		deviceID = wpID
	}
	if userEmail == "" {
		userEmail = wpEmail
	}
	return deviceID, userEmail
}

func readCloudDomainJoin() (deviceID, userEmail string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, cloudDomainJoinPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", ""
	}
	defer key.Close()
	return firstJoinInfoMatch(key, registry.LOCAL_MACHINE, cloudDomainJoinPath)
}

func readWorkplaceJoin() (deviceID, userEmail string) {
	usersKey, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", ""
	}
	defer usersKey.Close()

	sids, err := usersKey.ReadSubKeyNames(-1)
	if err != nil {
		return "", ""
	}

	for _, sid := range sids {
		if !isLoadedUserSID(sid) {
			continue
		}
		path := sid + `\` + workplaceJoinRel
		key, err := registry.OpenKey(registry.USERS, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		id, email := firstJoinInfoMatch(key, registry.USERS, path)
		key.Close()
		if deviceID == "" && id != "" {
			deviceID = id
		}
		if userEmail == "" && email != "" {
			userEmail = email
		}
		if deviceID != "" && userEmail != "" {
			break
		}
	}
	return deviceID, userEmail
}

func firstJoinInfoMatch(key registry.Key, root registry.Key, basePath string) (deviceID, userEmail string) {
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return "", ""
	}
	for _, name := range names {
		id, email := readJoinSubkey(root, basePath, name)
		if deviceID == "" && id != "" {
			deviceID = id
		}
		if userEmail == "" && email != "" {
			userEmail = email
		}
		if deviceID != "" && userEmail != "" {
			return deviceID, userEmail
		}
	}
	return deviceID, userEmail
}

func readJoinSubkey(root registry.Key, basePath, name string) (deviceID, userEmail string) {
	sub, err := registry.OpenKey(root, basePath+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer sub.Close()

	email, _, _ := sub.GetStringValue("UserEmail")
	userEmail = strings.TrimSpace(email)

	for _, valueName := range []string{"DeviceId", "Id"} {
		if v, _, err := sub.GetStringValue(valueName); err == nil {
			if v = strings.TrimSpace(v); v != "" {
				return strings.ToLower(v), userEmail
			}
		}
	}
	if looksLikeGUID(name) {
		return strings.ToLower(name), userEmail
	}
	return "", userEmail
}

func isLoadedUserSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") && !strings.Contains(sid, "_")
}

func looksLikeGUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
