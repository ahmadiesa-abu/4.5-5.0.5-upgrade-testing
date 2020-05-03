# 4.5/4.6-5.0.5-upgrade-testing
script to simulate upgrade for a pre-setup environment with wild card certificate and dns

# Prerequisites
* run: `pip install -r requirements.txt`
* this script consider that you have a 4.5/4.6 cluster ready for upgrade [ if not you can comment out the stuff of snapshot]

# Configuration 
* need to fill out the configuration : 
  * Openstack Credentials 
  * old Cluster IPs 
  * old Haproxy IP 
  * old Certificates

# What to Expect 
* the script will take a snapshot from the old cluster 
* copy the ssh keys 
* it will create 5.x cluster :
  * 3 DBs
  * 3 Rabbits
  * 3 Managers
* reconfigure the haproxy to point to the new managers
* restore snapshot 
* install agents
* validate the newly installed agents 
