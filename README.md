# Nodeport service load-balancing demo using eBpf 

## tc

tc eBpf demo of Nodeport (like) N-S load balancing and SNAT/ DNAT using recently added kfuncs to support connection tracking and NAT using eBpf programs.

Notes: 
- The design is based on Approach A2 as [documented here](https://gist.github.com/srampal/b300d1a1f847d18d362a55844944f7a7).
- The current version is an initial Proof of Concept/ demo currently meant to validate [Approach A2](https://gist.github.com/srampal/b300d1a1f847d18d362a55844944f7a7) and the use of the newly added kfuncs for managing kernel connection tracking (conntrack) tables.
- This requires a system built with a custom kernel currently (it has been tested using a kernel from bpf-next/ 6.0.0-rc3)
- To build, first recursively load all the sub-modules at the top of the repo (*git submodule update --init --recursive*), then 'make tc' under src 

### Executing the demo

For the initial demo, the eBpf program is invoked from a CLI command and not via a Kubernetes controller for services (this is to be addressed in a following rev). To run the demo, create a Kubernetes deployment and provide the NodePort and backends via the CLI invocation on the Kubernetes worker nodes. For example: *tc eth0 \<nodeport\> \<backend_ip_1\> \<backend_ip_2\> \<targetPort\>*. (For example *tc eth0 31000 10.240.1.2 10.240.1.3 80*). 

Additional details to be added with future updates ...
