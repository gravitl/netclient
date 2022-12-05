# README

## About

Netclient. A lightweight client GUI for [Netmaker](http://netmaker.io/).

## Development

Due to addition of the `github.com/gravitl/netclient` library, you will need root priviledges to run the app, even in dev mode.
Always skip automatic TS modules generation when building or starting dev mode with `-skipbindings` because 
the models of some Go types are not generated.
Only generate modules when you are sure. you will have to change the unkown types to any after generation.

### Cheatsheet

- Generate TS modules with `export WAILS_EXEC="$(which wails)" && sudo -E PATH=$PATH:$GOROOT/bin $WAILS_EXEC generate module && sudo chown -R "$(whoami)" ./*`
- Run dev mode with `export WAILS_EXEC="$(which wails)" && export NODE_PATH=/home/aceix/.volta/bin && sudo -E PATH=$PATH:$GOROOT/bin:$NODE_PATH $WAILS_EXEC dev -skipbindings`

_*actual paths might differ for you_


If you want to develop in a browser and have access to your Go methods,
there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

You can configure the project by editing `wails.json`. More information about the project settings can be found
here: https://wails.io/docs/reference/project-config

The `frontend` directory holds code for the UI. 
Make any UI changes only in this directory (inluding dependency installs like `npm install`).

## Building

To build a redistributable, production mode package, use `wails build -skipbindings` (might also need root access).
