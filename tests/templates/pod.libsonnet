{
    addLabels(labels)::
        if labels == '' then
            {}
        else
            {
                'labels': std.parseJson(labels)
            },


    specifyNode(node)::
        if node == '' then
            {}
        else
            {
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [
                                {
                                    "matchExpressions": [
                                        {
                                            "key": "kubernetes.io/hostname",
                                            "operator": "In",
                                            "values": [
                                                node
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
}
