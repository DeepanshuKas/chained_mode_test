local podinput = import 'pod.libsonnet';

function(name, image='noiro-quay.cisco.com/noiro/alpine:latest', namespace='default', labels='', node='')
{
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
        generateName: "%s-" % name,
        namespace: namespace,
    } + podinput.addLabels(labels),
    spec: {
		containers: [
			{
				image: image,
				command: [
					"/bin/sh",
					"-c",
					"sleep 60m"
				],
				imagePullPolicy: "IfNotPresent",
				name: "alpine"
			}
		],
		restartPolicy: "Always",
		terminationGracePeriodSeconds: 0
	} + podinput.specifyNode(node)
}
