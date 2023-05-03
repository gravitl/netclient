### To Build

## Head build

Linux: 
sudo apt-get install npm build-essential libgtk3 libwebkit libx11-dev
OR
sudo apt-get install npm build-essential libgtk-3-dev libwebkit2gtk-4.0 libx11-dev

- Prod
  - `cd gui/frontend/ && npm run build`
  - `go build -tags desktop,production -ldflags "-w -s"`
  - Windows:
    - `go build -tags desktop,production -ldflags "-w -s -H windowsgui"`
- Dev (GUI) `go build -tags dev -gcflags "all=-N -l"`

## Headless build
Linux: sudo apt-get install build-essential
- go build 
