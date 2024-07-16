# strongSwan osmo-epdg component

This repository contains a modified version of the strongswan code base to use it
together with [osmo-epdg](https://osmocom.org/projects/osmo-epdg/wiki/)
in order to operate a 3GPP ePDG (evolved Packet Data Gateway), for example to provide
VoWiFi services.

    [UE] <-> [strongswan] <-> [osmo-ePDG] <> [HSS]
                                          <> [PGW]

## example configuration

See `./osmo-epdg` for a full example configuration (both UE and ePDG).

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

## Funding

This project received funding through the [User-operated Internet Fund](https://nlnet.nl/useroperated), a fund established by [NLnet](https://nlnet.nl). Learn more at the [NLnet project page](https://nlnet.nl/project/Osmocom-ePDG).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
