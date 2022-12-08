### To Build

## Head build

Linux: 
sudo apt-get install npm build-essential libgtk3 libwebkit
- Prod
  - `cd gui/frontend/ && npm run build`
  - `go build -tags desktop,production -ldflags "-w -s"`
- Dev (GUI) `go build -tags dev -gcflags "all=-N -l"`

## Headless build
- go build -tags headless
