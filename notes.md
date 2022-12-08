### To Build

Linux: 
sudo apt-get install build-essential libgtk-3-dev libgtk-4-dev libwebkit2gtk-4.0-dev
- Prod
  - `cd gui/frontend/ && npm run build`
  - `go build -tags desktop,production -ldflags "-w -s"`
- Dev (GUI) `go build -tags dev -gcflags "all=-N -l"`
