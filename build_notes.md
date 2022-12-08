### To Build

Linux: 
sudo apt-get install npm build-essential libgtk3 libwebkit
- Prod
  - `cd gui/frontend/ && npm run build`
  - `go build -tags gui,desktop,production -ldflags "-w -s"`
- Dev (GUI) `go build -tags gui,dev -gcflags "all=-N -l"`
