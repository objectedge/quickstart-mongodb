#!/bin/bash

#################################################################
# Update the OS, install packages, initialize environment vars,
# and get the instance tags
#################################################################
yum -y update
yum install -y jq
yum install -y xfsprogs

source ./oe-orchestrator.sh -i
source ./config.sh

tags=`aws ec2 describe-tags --filters "Name=resource-id,Values=${AWS_INSTANCEID}"`

#################################################################
#  gatValue() - Read a value from the instance tags
#################################################################
getValue() {
    index=`echo $tags | jq '.[]' | jq '.[] | .Key == "'$1'"' | grep -n true | sed s/:.*//g | tr -d '\n'`
    (( index-- ))
    filter=".[$index]"
    result=`echo $tags | jq '.[]' | jq $filter.Value | sed s/\"//g | sed s/Primary.*/Primary/g | sed s/Secondary.*/Secondary/g | sed s/Arbiter.*/Arbiter/g | tr -d '\n'`
    echo $result
}

#################################################################
#  getEIP() - Get the Elastic IP associated with the instance
#################################################################
getEIP() {
    while true; do
        address=`aws ec2 describe-addresses --filters "Name=instance-id,Values=${AWS_INSTANCEID}"`
        IP=`echo $address | jq '.[]' | jq '.[]' | jq '.PublicIp' | sed s/\"//g`
        if [[ ! $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "Waiting for Elastic IP to be associated!.."
            sleep 5
        else
            echo "Got Elastic IP for instance: ${AWS_INSTANCEID}!"
            break
        fi
    done
    echo ${IP}
}

##version=`getValue MongoDBVersion`

# MongoDBVersion set inside config.sh
version=${MongoDBVersion}

if [ -z "$version" ] ; then
  version="3.2"
fi

echo "[mongodb-org-${version}]
name=MongoDB Repository
baseurl=http://repo.mongodb.org/yum/amazon/2013.03/mongodb-org/${version}/x86_64/
gpgcheck=0
enabled=1" > /etc/yum.repos.d/mongodb-org-${version}.repo

# To be safe, wait a bit for flush
sleep 5

yum --enablerepo=epel install node npm -y

yum install -y mongodb-org
yum install -y munin-node
yum install -y libcgroup
yum -y install mongo-10gen-server mongodb-org-shell
yum -y install sysstat

#################################################################
#  Figure out what kind of node we are and set some values
#################################################################
NODE_TYPE=`getValue Name`
# IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
IP=$(getEIP)
SHARD=s`getValue ReplicaShardIndex`
NODES=`getValue ClusterNodeCount`

#  Do NOT use timestamps here!!
# This has to be unique across multiple runs!
UNIQUE_NAME=MONGODB_${TABLE_NAMETAG}_${VPC}

#################################################################
#  Wait for all the nodes to synchronize so we have all IP addrs
#################################################################
if [ "${NODE_TYPE}" == "Primary" ]; then
    ./oe-orchestrator.sh -c -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -i "NodeType=${NODE_TYPE}"
    ./oe-orchestrator.sh -s "WORKING" -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -w "WORKING=${NODES}" -n "${SHARD}_${UNIQUE_NAME}"
    node_info=$(./oe-orchestrator.sh -g -n "${SHARD}_${UNIQUE_NAME}")
    IPADDRS=$(echo $node_info | jq '.PublicIp' | sed s/\"//g)
    N_TYPES=$(echo $node_info | jq '.NodeType' | sed s/\"//g)
    read -a IPADDRS <<< $IPADDRS
    read -a N_TYPES <<< $N_TYPES
else
    ./oe-orchestrator.sh -b -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -w "WORKING=1" -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -i "NodeType=${NODE_TYPE}"
    ./oe-orchestrator.sh -s "WORKING" -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -w "WORKING=${NODES}" -n "${SHARD}_${UNIQUE_NAME}"
fi

#################################################################
# Make filesystems, set ulimits and block read ahead on ALL nodes
#################################################################
mkfs.xfs -f /dev/xvdf
echo "/dev/xvdf /data xfs defaults,auto,noatime,noexec 0 0" | tee -a /etc/fstab
mkdir -p /data
mount /data
chown -R mongod:mongod /data
blockdev --setra 32 /dev/xvdf
rm -rf /etc/udev/rules.d/85-ebs.rules
touch /etc/udev/rules.d/85-ebs.rules
echo 'ACTION=="add", KERNEL=="'$1'", ATTR{bdi/read_ahead_kb}="16"' | tee -a /etc/udev/rules.d/85-ebs.rules
echo "* soft nofile 64000
* hard nofile 64000
* soft nproc 32000
* hard nproc 32000" > /etc/limits.conf
#################################################################
# End All Nodes
#################################################################

#################################################################
# Listen to all interfaces, not just local
#################################################################

enable_all_listen() {
  for f in /etc/mongo*.conf
  do
    sed -e '/bindIp/s/^/#/g' -i ${f}
    sed -e '/bind_ip/s/^/#/g' -i ${f}
    echo " Set listen to all interfaces : ${f}"
  done
}

check_primary() {
    expected_state=$1
    master_substr=\"ismaster\"\ :\ ${expected_state}
    while true; do
      check_master=$( mongo --eval "printjson(db.isMaster())" )
      log "${check_master}..."
      if [[ $check_master == *"$master_substr"* ]]; then
        log "Node is in desired state, proceed with security setup"
        break
      else
        log "Wait for node to become primary"
        sleep 10
      fi
    done
}

setup_security_common() {
    DDB_TABLE=$1
    auth_key=$(./oe-orchestrator.sh -f -n $DDB_TABLE)
    echo $auth_key > /mongo_auth/mongodb.key
    chmod 400 /mongo_auth/mongodb.key
    chown -R mongod:mongod /mongo_auth
    sed $'s/processManagement:/security: \\\n  authorization: enabled \\\n  keyFile: \/mongo_auth\/mongodb.key \\\n\\\n&/g' /etc/mongod.conf >> /tmp/mongod_sec.txt
    mv /tmp/mongod_sec.txt /etc/mongod.conf
}

setup_security_primary() {
    DDB_TABLE=$1
    port=27017
    MONGO_PASSWORD=$( cat /tmp/mongo_pass.txt )

mongo --port ${port} << EOF
use admin;
db.createUser(
  {
    user: "${MONGODB_ADMIN_USER}",
    pwd: "${MONGO_PASSWORD}",
    roles: [ { role: "root", db: "admin" } ]
  }
);
EOF

    service mongod stop
    ./oe-orchestrator.sh -k -n $DDB_TABLE
    sleep 5
    setup_security_common $DDB_TABLE
    sleep 5
    service mongod start
    sleep 10
    ./oe-orchestrator.sh -s "SECURED" -n $DDB_TABLE
}

#################################################################
# Setup MongoDB servers and config nodes
#################################################################
mkdir /var/run/mongod
chown mongod:mongod /var/run/mongod

enable_journal="true"
if [ "${NODE_TYPE}" == "Arbiter" ]; then
    log "Disable journal for arbiter node"
    enable_journal="false"
fi

echo "net:" > mongod.conf
echo "  port:" >> mongod.conf
echo "" >> mongod.conf
echo "systemLog:" >> mongod.conf
echo "  destination: file" >> mongod.conf
echo "  logAppend: true" >> mongod.conf
echo "  path: /log/mongod.log" >> mongod.conf
echo "" >> mongod.conf
echo "storage:" >> mongod.conf
echo "  dbPath: /data" >> mongod.conf
echo "  journal:" >> mongod.conf
echo "    enabled: $enable_journal" >> mongod.conf
echo "" >> mongod.conf
echo "processManagement:" >> mongod.conf
echo "  fork: true" >> mongod.conf
echo "  pidFilePath: /var/run/mongod/mongod.pid" >> mongod.conf

#################################################################
#  Enable munin plugins for iostat and iostat_ios
#################################################################
ln -s /usr/share/munin/plugins/iostat /etc/munin/plugins/iostat
ln -s /usr/share/munin/plugins/iostat_ios /etc/munin/plugins/iostat_ios
touch /var/lib/munin/plugin-state/iostat-ios.state
chown munin:munin /var/lib/munin/plugin-state/iostat-ios.state

#################################################################
# Make the filesystems, add persistent mounts
#################################################################
mkfs.xfs -f /dev/xvdg
mkfs.xfs -f /dev/xvdh

echo "/dev/xvdg /journal xfs defaults,auto,noatime,noexec 0 0" | tee -a /etc/fstab
echo "/dev/xvdh /log xfs defaults,auto,noatime,noexec 0 0" | tee -a /etc/fstab

#################################################################
# Make directories for data, journal, and logs
#################################################################
mkdir -p /journal
mount /journal

#################################################################
#  Figure out how much RAM we have and how to slice it up
#################################################################
memory=$(vmstat -s | grep "total memory" | sed -e 's/ total.*//g' | sed -e 's/[ ]//g' | tr -d '\n')
memory=$(printf %.0f $(echo "${memory} / 1024 / 1 * .9 / 1024" | bc))

if [ ${memory} -lt 1 ]; then
    memory=1
fi

#################################################################
#  Make data directories and add symbolic links for journal files
#################################################################

mkdir -p /data/
mkdir -p /journal/

  # Add links for journal to data directory
ln -s /journal/ /data/journal

mkdir -p /log
mount /log

#################################################################
# Change permissions to the directories
#################################################################
chown -R mongod:mongod /journal
chown -R mongod:mongod /log
chown -R mongod:mongod /data

#################################################################
# Clone the mongod config file and create cgroups for mongod
#################################################################
c=0
port=27017

cp mongod.conf /etc/mongod.conf
sed -i "s/.*port:.*/  port: ${port}/g" /etc/mongod.conf
echo "replication:" >> /etc/mongod.conf
echo "  replSetName: ${SHARD}" >> /etc/mongod.conf

echo CGROUP_DAEMON="memory:mongod" > /etc/sysconfig/mongod

echo "mount {
    cpuset  = /cgroup/cpuset;
    cpu     = /cgroup/cpu;
    cpuacct = /cgroup/cpuacct;
    memory  = /cgroup/memory;
    devices = /cgroup/devices;
  }

  group mongod {
    perm {
      admin {
        uid = mongod;
        gid = mongod;
      }
      task {
        uid = mongod;
        gid = mongod;
      }
    }
    memory {
      memory.limit_in_bytes = ${memory}G;
      }
  }" > /etc/cgconfig.conf


#################################################################
#  Start cgconfig, munin-node, and all mongod processes
#################################################################
chkconfig cgconfig on
service cgconfig start

chkconfig munin-node on
service munin-node start

chkconfig mongod on
enable_all_listen
service mongod start

#################################################################
#  Primaries initiate replica sets
#################################################################
if [[ "$NODE_TYPE" == "Primary" ]]; then

    #################################################################
    # Wait unitil all the hosts for the replica set are responding
    # Notice that arbiter set will have no admin database, but it's fine
    #################################################################
    for addr in "${IPADDRS[@]}"
    do
        addr="${addr%\"}"
        addr="${addr#\"}"

        echo ${addr}:${port}
        while [ true ]; do

            echo "mongo --host ${addr} --port ${port}"

mongo --host ${addr} --port ${port} << EOF
use admin
EOF

            if [ $? -eq 0 ]; then
                break
            fi
            sleep 5
        done
    done

    #################################################################
    # Configure the replica sets, set this host as Primary with
    # highest priority
    #################################################################
    if [ "${NODES}" == "3" ]; then
        port=27017
        conf="{\"_id\" : \"${SHARD}\", \"version\" : 1, \"members\" : ["
        node=1
        # IPADDRS and N_TYPES should have the same length
        for i in "${!IPADDRS[@]}"
        do
            addr="${IPADDRS[$i]}"
            addr="${addr%\"}"
            addr="${addr#\"}"

            ntype="${N_TYPES[$i]}"
            ntype="${ntype%\"}"
            ntype="${ntype#\"}"

            priority=5
            if [ "${addr}" == "${IP}" ]; then
                priority=10
            fi
            arbiter_only=false
            if [[ "$ntype" == "Arbiter" ]]; then
                arbiter_only=true
            fi
            conf="${conf}{\"_id\" : ${node}, \"host\" :\"${addr}:${port}\", \"priority\" : ${priority}, \"arbiterOnly\" : $arbiter_only}"

            if [ $node -lt ${NODES} ]; then
                conf=${conf}","
            fi

            (( node++ ))
        done

        conf=${conf}"]}"
        echo ${conf}

mongo --port ${port} << EOF
rs.initiate(${conf})
EOF

        if [ $? -ne 0 ]; then
            # Houston, we've had a problem here...
            ./signalFinalStatus.sh 1
        fi
    else
        port=27017

        priority=10
        conf="{\"_id\" : \"${SHARD}\", \"version\" : 1, \"members\" : ["
        conf="${conf}{\"_id\" : 1, \"host\" :\"${IP}:${port}\", \"priority\":${priority}}"
        conf=${conf}"]}"

mongo --port ${port} << EOF
rs.initiate(${conf})
EOF

    fi

    #################################################################
    #  Update status to FINISHED, if this is s0 then wait on the rest
    #  of the nodes to finish and remove orchestration tables
    #################################################################
    ./oe-orchestrator.sh -s "FINISHED" -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -w "FINISHED=${NODES}" -n "${SHARD}_${UNIQUE_NAME}"

    echo "Setting up security, bootstrap table: " "${SHARD}_${UNIQUE_NAME}"
    # wait for mongo to become primary
    sleep 10
    check_primary true

    setup_security_primary "${SHARD}_${UNIQUE_NAME}"

    ./oe-orchestrator.sh -w "SECURED=${NODES}" -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -d -n "${SHARD}_${UNIQUE_NAME}"
    rm /tmp/mongo_pass.txt
else
    #################################################################
    #  Update status of Secondary to FINISHED
    #################################################################
    ./oe-orchestrator.sh -s "FINISHED" -n "${SHARD}_${UNIQUE_NAME}"
    ./oe-orchestrator.sh -w "FINISHED=${NODES}" -n "${SHARD}_${UNIQUE_NAME}"

    ./oe-orchestrator.sh -w "SECURED=1" -n "${SHARD}_${UNIQUE_NAME}"
    service mongod stop
    setup_security_common "${SHARD}_${UNIQUE_NAME}"
    service mongod start
    ./oe-orchestrator.sh -s "SECURED" -n "${SHARD}_${UNIQUE_NAME}"
    rm /tmp/mongo_pass.txt

fi

# TBD - Add custom CloudWatch Metrics for MongoDB

# exit with 0 for SUCCESS
exit 0
