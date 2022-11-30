# Nodeport service load-balancing demo using eBpf 

## tc

tc eBpf demo of Nodeport (like) N-S load balancing and SNAT/ DNAT using recently added kfuncs to support connection tracking and NAT using eBpf programs.

Notes: 
- this requires a system built with a custom kernel currently (using kernel from bpf-next/ 6.0.0-rc3 or later)
- To build, first recursively load all the sub-modules at the top of the repo (git submodule update --init --recursive), then 'make tc' under src 
- The design is based on Approach A2 as documented [here](https://gist.github.com/srampal/b300d1a1f847d18d362a55844944f7a7).

### Executing the demo

For the initial demo, the eBpf program is invoked from a CLI command and not via a Kubernetes controller for services (this is to be addressed in a following rev). To run the demo, create a Kubernetes deployment and provide the NodePort and backends via the CLI invocation on the Kubernetes worker nodes. For example: *tc eth0 <nodeport> <backend_ip_1> <backend_ip_2> <targetPort>

Additional details to be added ...

