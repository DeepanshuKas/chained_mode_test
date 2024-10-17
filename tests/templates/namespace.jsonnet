local ns = import 'ns.libsonnet';

function (name, labels='')
{
    apiVersion: "v1",
    kind: "Namespace",
    metadata: {
        name: name
    } + ns.addNs(labels)
}
