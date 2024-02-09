# strongSwan osmo-epdg component

- strongswan + a osmo-epdg plugins

## example configuration

See ./osmo-epdg for a full example configuration (both UE and ePDG).

The ePDG must use the address 192.168.0.2

## how to build

```
apt install libosmocore-dev
```

```
./autogen.sh
./configure \
	--enable-eap-aka \
	--enable-eap-aka-3gpp \
	--enable-eap-aka-3gpp2 \
	--enable-eap-simaka-reauth \
	--enable-systemd \
	--enable-save-keys \
	--enable-p-cscf \
	--enable-osmo-epdg

```
