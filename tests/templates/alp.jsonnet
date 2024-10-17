local podinput = import 'pod.libsonnet';

function(name, namespace='default', labels='')
{
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
        name: name,
        namespace: namespace,
    } + podinput.addLabels(labels),
    spec: {
		containers: [
			{
				image: "noiro-quay.cisco.com/noiro/alpine:latest",
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
	}
}
