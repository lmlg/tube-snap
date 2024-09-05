#! /bin/sh

snap connect tube:block-devices
snap connect tube:hugepages-control
snap connect tube:shared-memory
snap connect tube:hardware-observe
snap connect tube:cpu-control
snap connect tube:process-control
snap connect tube:network
snap connect tube:network-bind
snap connect tube:network-control
snap connect tube:mount-observe
