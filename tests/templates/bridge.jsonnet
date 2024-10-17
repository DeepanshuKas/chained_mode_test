function(name, mode, vlan, min_vlan, max_vlan)
{
    "cniVersion": "0.3.1",
    "name": name,
    "plugins": [
        {
            "cniVersion": "0.3.1",
            "name": name,
            "type": "bridge",
            "bridge": name,
            "vlanTrunk": [
                {
                    "id": vlan
                },
                {
                    "minID": min_vlan,
                    "maxID": max_vlan
                }
            ],
            "isDefaultGateway": ( if mode == 'l3' then true else false ),
            "ipam": ( if mode == 'l3' then {
                "type": "whereabouts",
                "range": "192.168.128.0/24",
                "exclude": ["192.168.128.0/32", "192.168.128.1/32", "192.168.128.254/32"]
            } else {})
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
