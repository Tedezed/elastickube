#!/bin/bash -e

user=$(whoami)
ELASTICBOX_PATH="/var/elasticbox"

# Install ElasticBox bootstrap
sudo apt-get -y update
sudo apt-get -y install python-pip curl virtualenv

virtualenv .viertualenv

source .viertualenv/bin/activate

pip install --no-compile elasticbox-docker

# Create code and log folder
sudo mkdir -p /var/log/elastickube && sudo chown $user:$user /var/log/elastickube
sudo mkdir -p /opt/elastickube && sudo chown -R $user:$user /opt/elastickube

sudo mkdir -p /var/elasticbox

sudo bash -- << \
_____________EXECUTE_BOXES_____________

export DEBIAN_FRONTEND=noninteractive
export ELASTICBOX_PATH=/opt/elastickube/build
export ELASTICBOX_INSTANCE_PATH=${ELASTICBOX_PATH}

.viertualenv/bin/elasticbox run --install --exit
_____________EXECUTE_BOXES_____________

echo "Exit .viertualenv, you need activate"
deactivate