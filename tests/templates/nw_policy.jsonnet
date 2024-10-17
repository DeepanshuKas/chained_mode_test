local nwpol = import 'nw_policy.libsonnet';


function(name, ingress='', egress='', pod_selector='',  namespace='', ingress_rules='', egress_rules='')
{
	apiVersion: "networking.k8s.io/v1",
	kind: "NetworkPolicy",
	metadata: {
		generateName: "%s-" % name,
		labels: {
		    test: "test-%s" % name
		}
	} + nwpol.emptyOrObject('namespace', '%s')(namespace),
	spec: {
		policyTypes: [] + (if ingress != '' then ["Ingress"] else []) + (if egress != '' then ["Egress"] else []),

	} + nwpol.addPodSelector(pod_selector) + nwpol.addIngressRules(ingress_rules) + nwpol.addEgressRules(egress_rules)
}
