# Netclient v0.24.1

## Whats New ✨

- IPv6 and Dual Stack Networks Support Across Platform
- Turned Off Hole Punching For Static Hosts
- Endpoint Detection Can Now Be Turned Off By Setting `ENDPOINT_DETECTION=false` On Server Config

## What's Fixed/Improved 🛠

- Fixed The Issues Around Config Getting Corrupted
- Scalability Fixes
- Improved Endpoint Detection Logic, Optimised To Throttle The Number Of Open Test Connections
- Improved FailedOver Logic To Work At Scale
- Fixed Egress Routes In Dual Stack Netmaker Overlay Networks
- Fixed Windows Adapter Issues
- Added Improvments For Handling Static Host Args On `netclient join` Command
- Mac IPv6 addresses/route issues
- Fixed Client Connectivity Metrics Data

## Known Issues 🐞

- Windows Intermittent Issues With Interface Disappearing When Joined On Multiple Networks
- Erratic Traffic Data In Metrics
- `netclient server leave`  Leaves a Stale Node Record In At Least One Network When Part Of Multiple Networks, But Can Be Deleted From The UI.
- On Darwin Stale Egress Route Entries Remain On The Machine After Removing Egress Range Or Removing The Egress Server



