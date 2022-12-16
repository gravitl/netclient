### To Build

## Head build

Linux: 
sudo apt-get install npm build-essential libgtk3 libwebkit libpcap-dev
- Prod
  - `cd gui/frontend/ && npm run build`
  - `go build -tags desktop,production -ldflags "-w -s"`
  - Windows:
    - `go build -tags desktop,production -ldflags "-w -s -H windowsgui"`
- Dev (GUI) `go build -tags dev -gcflags "all=-N -l"`

## Headless build
Linux: sudo apt-get install build-essential libpcap-dev
- go build -tags headless
