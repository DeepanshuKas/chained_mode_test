function(name, vlan, min_vlan, max_vlan)
{
    "cniVersion": "0.3.1",
    "name": name,
    "plugins": [
        {
            "cniVersion": "0.3.1",
            "name": name,
            "type": "ovs",
            "bridge": name,
            "vlanTrunk": [
                {
                    "id": vlan
                },
                {
                    "minID": min_vlan,
                    "maxID": max_vlan
                }
            ]
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