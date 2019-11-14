#! /bin/bash

if [ "$1" == "--server" ]; then

if [ ! -f nic/setup_teardown/src/build/dataplane.nffw ]; then
	echo "Cannot find nic/setup_teardown/src/build/dataplane.nffw.. please run init_nic.sh first"
	exit 1
fi

cd nic/setup_teardown; ./load_p4; cd ../..
	
elif [ "$1" == "--proxy" ]; then

if [ ! -f nic/splice/src/build/splice.nffw ]; then		
	echo "Cannot find nic/splice/src/build/splice.nffw.. please run init_nic.sh first"
	exit 1
fi

cd nic/splice; ./load_p4; cd ../..

fi
