function(name, mode='l2', master='bond1')
{
    "cniVersion": "0.3.1",
    "name": name,
    "plugins": [
        {
            "cniVersion": "0.3.1",
            "name": name,
            "type": "ipvlan",
            "mode": mode,
            "master": master,
            "ipam": {
                "type": "whereabouts",
                "range": "192.168.128.0/24",
                "exclude": ["192.168.128.0/32", "192.168.128.1/32", "192.168.128.254/32"]
            }
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
