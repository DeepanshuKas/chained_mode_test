function(name, vlan=0)
{
    "cniVersion": "0.3.1",
    "name": name,
    "plugins": [
        {
            "name": name,
            "cniVersion": "0.3.1",
            "type": "sriov",
            "vlan": vlan,
            "trust": "on",
            "vlanQoS": 0,
            "capabilities": {
                "ips": true
            },
            "link_state": "auto"
        },
        {
            "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ],
            "type": "netop-cni",
            "chaining-mode": true,
            "log-level": "debug",
            "log-file": "/var/log/netopcni.log"
        }
    ]
}
