# Nodeport service load-balancing demo using eBpf 

## tc

tc eBpf demo of Nodeport (like) N-S load balancing and SNAT/ DNAT using recently added kfuncs to support connection tracking and NAT using eBpf programs.

Notes: 
- this requires a system built with a custom kernel currently (using kernel from bpf-next/ 6.0.0-rc3 or later)
- To build, first recursively load all the sub-modules at the top of the repo (git submodule update --init --recursive), then 'make tc' under src 

Details to be added ...

